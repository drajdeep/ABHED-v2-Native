/*
 * Copyright 2026 Rajdeep Das, IEM-UEM, Kolkata, India
 * SPDX-License-Identifier: Apache-2.0
 * Part of ABHED-v2. See the LICENSE and NOTICE files for terms and attribution.
 *
 * abhed-signzone: sign a zone with ECDSAP256SHA256, ML-DSA-44 or ML-DSA-44-MTL-SHAKE-128.
 *
 * MTL signing is batch signing: every RRset that is new, changed or close to expiry becomes
 * a leaf of the zone's node set, and ONE ML-DSA-44 signature covers the resulting ladder.
 * The node set and the leaf map are kept in the state directory, so re-signing continues the
 * same series (same SID, append-only) and unchanged RRsets keep their leaves. Every MTL RRSIG
 * in the output is a full signature (MTL-Type 0x01), as draft-kaizer-dnsop-ml-dsa-mtl-dnssec
 * requires; servers may serve condensed forms per draft-hdong-...-sigtag-ext.
 */
#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <abhed/abhed.h>
#include "keyfile.h"

#define MAX_KEYS 8

typedef struct {
    ldns_rdf *owner;          /* borrowed from the dnssec zone */
    ldns_rr_type type;
    ldns_rr_list *rrs;        /* owned list, borrowed rrs */
    abhed_key *key;
    int rank;                 /* hot-last placement: larger = later leaf */
    char ident[600];
    uint8_t digest[32];
    uint64_t leaf;
    uint32_t inc, exp;
    int reuse;
} job;

static struct {
    const char *origin_s, *in, *out, *statedir, *order;
    int validity_days, refresh_days, new_series, quiet;
    long now;
} opt = {NULL, NULL, NULL, NULL, "hot-last", 14, 3, 0, 0, 0};

static void die(const char *fmt, const char *a)
{
    fprintf(stderr, "abhed-signzone: ");
    fprintf(stderr, fmt, a);
    fprintf(stderr, "\n");
    exit(1);
}

static void usage(void)
{
    fprintf(stderr,
        "usage: abhed-signzone -o origin -f signed.zone -k keyprefix [-k keyprefix ...]\n"
        "                      [-s statedir] [-e days] [-r days] [-l hot-last|canonical]\n"
        "                      [-t unixtime] [-N] [-q] unsigned.zone\n"
        "  -k  key file prefix (from abhed-keygen). Flags 257 signs DNSKEY; 256 signs the rest.\n"
        "      With only a 257 key it signs everything (CSK).\n"
        "  -s  directory for MTL series state (required for MTL keys)\n"
        "  -e  signature validity in days (default 14)\n"
        "  -r  re-sign RRsets whose signature expires within this many days (default 3)\n"
        "  -l  MTL leaf placement (default hot-last: apex SOA/DNSKEY/NS/NSEC get short proofs)\n"
        "  -N  start a new MTL series (new SID) even if state exists\n"
        "  -t  signing time (default now)\n");
    exit(2);
}

static void hexs(char *out, const uint8_t *b, size_t n)
{
    for (size_t i = 0; i < n; i++) sprintf(out + 2 * i, "%02x", b[i]);
}

static int unhex(uint8_t *out, const char *s, size_t n)
{
    if (strlen(s) != 2 * n) return -1;
    for (size_t i = 0; i < n; i++) if (sscanf(s + 2 * i, "%2hhx", &out[i]) != 1) return -1;
    return 0;
}

/* canonical RRset wire (RFC 4034 6.3), TTL replaced by orig_ttl */
static void canonical_rrset(ldns_buffer *b, ldns_rr_list *rrs, uint32_t orig_ttl)
{
    ldns_rr_list *c = ldns_rr_list_clone(rrs);
    for (size_t i = 0; i < ldns_rr_list_rr_count(c); i++) {
        ldns_rr *rr = ldns_rr_list_rr(c, i);
        ldns_rr2canonical(rr);
        ldns_rr_set_ttl(rr, orig_ttl);
    }
    ldns_rr_list_sort(c);
    ldns_rr *prev = NULL;
    for (size_t i = 0; i < ldns_rr_list_rr_count(c); i++) {
        ldns_rr *rr = ldns_rr_list_rr(c, i);
        if (prev && ldns_rr_compare(prev, rr) == 0) continue;
        ldns_rr2buffer_wire_canonical(b, rr, LDNS_SECTION_ANSWER);
        prev = rr;
    }
    ldns_rr_list_deep_free(c);
}

static uint8_t label_count(const ldns_rdf *owner)
{
    uint8_t n = ldns_dname_label_count(owner);
    if (n > 0 && ldns_rdf_size(owner) > 1 && ldns_rdf_data(owner)[0] == 1 && ldns_rdf_data(owner)[1] == '*') n--;
    return n;
}

static ldns_rr *rrsig_header(job *j, const ldns_rdf *origin, uint32_t inc, uint32_t exp)
{
    ldns_rr *first = ldns_rr_list_rr(j->rrs, 0);
    uint32_t ttl = ldns_rr_ttl(first);
    ldns_rr *s = ldns_rr_new();
    ldns_rr_set_type(s, LDNS_RR_TYPE_RRSIG);
    ldns_rr_set_owner(s, ldns_rdf_clone(j->owner));
    ldns_rr_set_ttl(s, ttl);
    ldns_rr_push_rdf(s, ldns_native2rdf_int16(LDNS_RDF_TYPE_TYPE, j->type));
    ldns_rr_push_rdf(s, ldns_native2rdf_int8(LDNS_RDF_TYPE_ALG, (uint8_t)j->key->alg));
    ldns_rr_push_rdf(s, ldns_native2rdf_int8(LDNS_RDF_TYPE_INT8, label_count(j->owner)));
    ldns_rr_push_rdf(s, ldns_native2rdf_int32(LDNS_RDF_TYPE_INT32, ttl));
    ldns_rr_push_rdf(s, ldns_native2rdf_int32(LDNS_RDF_TYPE_TIME, exp));
    ldns_rr_push_rdf(s, ldns_native2rdf_int32(LDNS_RDF_TYPE_TIME, inc));
    ldns_rr_push_rdf(s, ldns_native2rdf_int16(LDNS_RDF_TYPE_INT16, j->key->tag));
    ldns_rdf *signer = ldns_rdf_clone(origin);
    ldns_dname2canonical(signer);
    ldns_rr_push_rdf(s, signer);
    return s;
}

/* RFC 4034 3.1.8.1 signing data for job j with the given header */
static ldns_buffer *signing_data(job *j, ldns_rr *hdr)
{
    ldns_buffer *b = ldns_buffer_new(4096);
    for (size_t i = 0; i < 8; i++)            /* RRSIG RDATA without the signature field */
        ldns_rdf2buffer_wire_canonical(b, ldns_rr_rdf(hdr, i));
    canonical_rrset(b, j->rrs, ldns_rr_ttl(ldns_rr_list_rr(j->rrs, 0)));
    return b;
}

static void push_sig(ldns_rr *hdr, const uint8_t *sig, size_t len)
{
    ldns_rr_push_rdf(hdr, ldns_rdf_new_frm_data(LDNS_RDF_TYPE_B64, len, sig));
}

static int rank_of(const ldns_rdf *owner, const ldns_rdf *origin, ldns_rr_type t)
{
    if (strcmp(opt.order, "hot-last") || ldns_dname_compare(owner, origin) != 0) return 0;
    switch (t) {                               /* SOA is in every negative answer: last */
    case LDNS_RR_TYPE_NSEC: return 1;
    case LDNS_RR_TYPE_NS: return 2;
    case LDNS_RR_TYPE_DNSKEY: return 3;
    case LDNS_RR_TYPE_SOA: return 4;
    default: return 0;
    }
}

static int cmp_rank(const void *a, const void *b)
{
    const job *x = *(job *const *)a, *y = *(job *const *)b;
    if (x->rank != y->rank) return x->rank - y->rank;
    int c = ldns_dname_compare(x->owner, y->owner);
    return c ? c : (int)x->type - (int)y->type;
}

/* ------------------------------------------------------------------ MTL leaf map */
typedef struct { char ident[600]; uint8_t digest[32]; uint64_t leaf; uint32_t inc, exp; } lentry;

static lentry *load_leafmap(const char *path, const char *pubid, size_t *n)
{
    *n = 0;
    FILE *f = fopen(path, "r");
    if (!f) return NULL;
    char line[1200], id[200];
    if (!fgets(line, sizeof line, f) || sscanf(line, "ABHED-LEAFMAP 1 %199s", id) != 1) {
        fclose(f); die("%s: not a leaf map", path);
    }
    if (strcmp(id, pubid) && !opt.new_series) {
        fclose(f);
        die("%s belongs to a different MTL key. Use -N to start a new series.", path);
    }
    size_t cap = 1024;
    lentry *v = malloc(cap * sizeof *v);
    while (fgets(line, sizeof line, f)) {
        char ident[600], dg[80];
        unsigned long long leaf;
        unsigned inc, exp;
        if (sscanf(line, "%599s %79s %llu %u %u", ident, dg, &leaf, &inc, &exp) != 5) continue;
        if (*n == cap) v = realloc(v, (cap *= 2) * sizeof *v);
        snprintf(v[*n].ident, sizeof v[*n].ident, "%s", ident);
        if (unhex(v[*n].digest, dg, 32)) continue;
        v[*n].leaf = leaf; v[*n].inc = inc; v[*n].exp = exp;
        (*n)++;
    }
    fclose(f);
    return v;
}

static int cmp_lentry(const void *a, const void *b)
{
    return strcmp(((const lentry *)a)->ident, ((const lentry *)b)->ident);
}

static void write_atomic(const char *path, const char *content_path)
{
    if (rename(content_path, path) != 0) die("cannot rename to %s", path);
}

int main(int argc, char **argv)
{
    const char *keyp[MAX_KEYS];
    int nkeys = 0, c;
    opt.now = time(NULL);
    while ((c = getopt(argc, argv, "o:f:k:s:e:r:l:t:Nqh")) != -1) {
        switch (c) {
        case 'o': opt.origin_s = optarg; break;
        case 'f': opt.out = optarg; break;
        case 'k': if (nkeys < MAX_KEYS) keyp[nkeys++] = optarg; break;
        case 's': opt.statedir = optarg; break;
        case 'e': opt.validity_days = atoi(optarg); break;
        case 'r': opt.refresh_days = atoi(optarg); break;
        case 'l': opt.order = optarg; break;
        case 't': opt.now = atol(optarg); break;
        case 'N': opt.new_series = 1; break;
        case 'q': opt.quiet = 1; break;
        default: usage();
        }
    }
    if (!opt.origin_s || !opt.out || !nkeys || optind != argc - 1) usage();
    opt.in = argv[optind];
    if (strcmp(opt.order, "hot-last") && strcmp(opt.order, "canonical")) usage();

    ldns_rdf *origin = ldns_dname_new_frm_str(opt.origin_s);
    if (!origin) die("bad origin %s", opt.origin_s);
    ldns_dname2canonical(origin);

    abhed_key keys[MAX_KEYS];
    abhed_key *ksk = NULL, *zsk = NULL;
    for (int i = 0; i < nkeys; i++) {
        if (abhed_key_load(&keys[i], keyp[i])) die("cannot load key %s", keyp[i]);
        if (ldns_dname_compare(ldns_rr_owner(keys[i].dnskey), origin) != 0) die("key %s is for another zone", keyp[i]);
        if (keys[i].flags & 1) { if (!ksk) ksk = &keys[i]; }
        else if (!zsk) zsk = &keys[i];
    }
    if (!ksk) ksk = zsk;
    if (!zsk) zsk = ksk;
    if (ksk->alg == ABHED_ALG_MTL && zsk->alg == ABHED_ALG_MTL && ksk != zsk)
        die("%s", "two MTL keys in one zone are not supported (use one MTL CSK, or an ML-DSA-44 KSK + MTL ZSK)");
    abhed_key *mtlkey = zsk->alg == ABHED_ALG_MTL ? zsk : ksk->alg == ABHED_ALG_MTL ? ksk : NULL;
    if (mtlkey && !opt.statedir) die("%s", "MTL keys need a state directory (-s)");

    /* ---- read the zone, drop old DNSSEC records, add DNSKEYs, build NSEC chain */
    FILE *f = fopen(opt.in, "r");
    if (!f) die("cannot open %s", opt.in);
    ldns_zone *z = NULL;
    int line = 0;
    ldns_status st = ldns_zone_new_frm_fp_l(&z, f, origin, 3600, LDNS_RR_CLASS_IN, &line);
    fclose(f);
    if (st != LDNS_STATUS_OK) {
        fprintf(stderr, "abhed-signzone: %s line %d: %s\n", opt.in, line, ldns_get_errorstr_by_id(st));
        return 1;
    }
    ldns_dnssec_zone *dz = ldns_dnssec_zone_new();
    ldns_dnssec_zone_add_rr(dz, ldns_rr_clone(ldns_zone_soa(z)));
    for (size_t i = 0; i < ldns_rr_list_rr_count(ldns_zone_rrs(z)); i++) {
        ldns_rr *rr = ldns_rr_list_rr(ldns_zone_rrs(z), i);
        ldns_rr_type t = ldns_rr_get_type(rr);
        if (t == LDNS_RR_TYPE_RRSIG || t == LDNS_RR_TYPE_NSEC || t == LDNS_RR_TYPE_NSEC3 ||
            (t == LDNS_RR_TYPE_DNSKEY && ldns_dname_compare(ldns_rr_owner(rr), origin) == 0)) continue;
        ldns_dname2canonical(ldns_rr_owner(rr));
        ldns_dnssec_zone_add_rr(dz, ldns_rr_clone(rr));
    }
    for (int i = 0; i < nkeys; i++) ldns_dnssec_zone_add_rr(dz, ldns_rr_clone(keys[i].dnskey));
    ldns_dnssec_zone_mark_glue(dz);
    ldns_rr_list *new_nsecs = ldns_rr_list_new();
    if (ldns_dnssec_zone_create_nsecs(dz, new_nsecs) != LDNS_STATUS_OK) die("%s", "NSEC chain creation failed");

    /* ---- collect the RRsets to sign */
    size_t njobs = 0, cap = 4096;
    job *jobs = calloc(cap, sizeof *jobs);
    ldns_rbnode_t *node = ldns_rbtree_first(dz->names);
    while (node != LDNS_RBTREE_NULL) {
        ldns_dnssec_name *nm = (ldns_dnssec_name *)node->data;
        node = ldns_rbtree_next(node);
        if (nm->is_glue) continue;
        int cut = 0;
        for (ldns_dnssec_rrsets *s = nm->rrsets; s; s = s->next)
            if (s->type == LDNS_RR_TYPE_NS && ldns_dname_compare(nm->name, origin) != 0) cut = 1;
        for (int pass = 0; pass < 2; pass++) {
            ldns_dnssec_rrsets *s = nm->rrsets;
            for (;;) {
                ldns_rr_type t;
                ldns_rr_list *l = ldns_rr_list_new();
                if (pass == 0) {
                    if (!s) { ldns_rr_list_free(l); break; }
                    t = s->type;
                    for (ldns_dnssec_rrs *r = s->rrs; r; r = r->next) ldns_rr_list_push_rr(l, r->rr);
                    s = s->next;
                    if (cut && t != LDNS_RR_TYPE_DS) { ldns_rr_list_free(l); continue; }
                } else {
                    if (!nm->nsec) { ldns_rr_list_free(l); break; }
                    t = LDNS_RR_TYPE_NSEC;
                    ldns_rr_list_push_rr(l, nm->nsec);
                }
                if (njobs == cap) { jobs = realloc(jobs, (cap *= 2) * sizeof *jobs); memset(jobs + njobs, 0, (cap - njobs) * sizeof *jobs); }
                job *j = &jobs[njobs++];
                j->owner = nm->name;
                j->type = t;
                j->rrs = l;
                j->key = t == LDNS_RR_TYPE_DNSKEY ? ksk : zsk;
                j->rank = rank_of(nm->name, origin, t);
                char *on = ldns_rdf2str(nm->name);
                snprintf(j->ident, sizeof j->ident, "%s|%u", on, (unsigned)t);
                free(on);
                if (pass == 1) break;
            }
        }
    }

    uint32_t inc = (uint32_t)(opt.now - 3600), exp = (uint32_t)(opt.now + 86400L * opt.validity_days);
    ldns_rr_list *sigs = ldns_rr_list_new();
    size_t n_mldsa = 0, n_ecdsa = 0, n_new = 0;

    /* ---- non-MTL signatures */
    for (size_t i = 0; i < njobs; i++) {
        job *j = &jobs[i];
        if (j->key->alg == ABHED_ALG_MTL) continue;
        ldns_rr *h = rrsig_header(j, origin, inc, exp);
        ldns_buffer *b = signing_data(j, h);
        if (j->key->alg == ABHED_ALG_ECDSAP256) {
            ldns_rdf *sig = ldns_sign_public_buffer(b, j->key->ldnskey);
            if (!sig) die("ECDSA signing failed for %s", j->ident);
            ldns_rr_push_rdf(h, sig);
            n_ecdsa++;
        } else {
            static uint8_t sig[ABHED_MLDSA44_SIG_LEN];
            size_t sl;
            if (abhed_mldsa44_sign(sig, &sl, ldns_buffer_begin(b), ldns_buffer_position(b), j->key->sk))
                die("ML-DSA-44 signing failed for %s", j->ident);
            push_sig(h, sig, sl);
            n_mldsa++;
        }
        ldns_buffer_free(b);
        ldns_rr_list_push_rr(sigs, h);
    }

    /* ---- MTL batch */
    abhed_nodeset *ns = NULL;
    abhed_ladder ladder;
    size_t mtl_jobs = 0;
    char nspath[4200] = "", lmpath[4200] = "";
    if (mtlkey) {
        uint8_t pubid[16];
        ldns_rdf *pk = ldns_rr_dnskey_key(mtlkey->dnskey);
        abhed_cshake128(pubid, 16, ldns_rdf_data(pk), ldns_rdf_size(pk), (const uint8_t *)"ABHEDKEY", 8);
        char pubhex[40];
        hexs(pubhex, pubid, 16);
        mkdir(opt.statedir, 0700);
        char *zn = ldns_rdf2str(origin);
        snprintf(nspath, sizeof nspath, "%s/%snodeset", opt.statedir, zn);
        snprintf(lmpath, sizeof lmpath, "%s/%sleafmap", opt.statedir, zn);
        free(zn);
        size_t nlm = 0;
        lentry *lm = opt.new_series ? NULL : load_leafmap(lmpath, pubhex, &nlm);
        if (lm) qsort(lm, nlm, sizeof *lm, cmp_lentry);
        if (!opt.new_series && lm) {
            ns = abhed_ns_load(nspath);
            if (!ns) die("%s: leaf map exists but node set cannot be read", nspath);
        }
        if (!ns) { ns = abhed_ns_new(NULL); lm = NULL; nlm = 0; }

        job **todo = malloc(njobs * sizeof *todo);
        size_t ntodo = 0;
        for (size_t i = 0; i < njobs; i++) {
            job *j = &jobs[i];
            if (j->key->alg != ABHED_ALG_MTL) continue;
            mtl_jobs++;
            ldns_buffer *b = ldns_buffer_new(4096);
            canonical_rrset(b, j->rrs, ldns_rr_ttl(ldns_rr_list_rr(j->rrs, 0)));
            abhed_cshake128(j->digest, 32, ldns_buffer_begin(b), ldns_buffer_position(b), (const uint8_t *)"ABHEDDIG", 8);
            ldns_buffer_free(b);
            lentry key, *e = NULL;
            snprintf(key.ident, sizeof key.ident, "%s", j->ident);
            if (lm) e = bsearch(&key, lm, nlm, sizeof *lm, cmp_lentry);
            if (e && !memcmp(e->digest, j->digest, 32) && (long)e->exp - opt.now > 86400L * opt.refresh_days &&
                e->leaf < abhed_ns_count(ns)) {
                j->reuse = 1; j->leaf = e->leaf; j->inc = e->inc; j->exp = e->exp;
            } else {
                todo[ntodo++] = j;
            }
        }
        qsort(todo, ntodo, sizeof *todo, cmp_rank);
        for (size_t i = 0; i < ntodo; i++) {
            job *j = todo[i];
            j->inc = inc; j->exp = exp;
            ldns_rr *h = rrsig_header(j, origin, inc, exp);
            ldns_buffer *b = signing_data(j, h);
            j->leaf = abhed_ns_append(ns, ldns_buffer_begin(b), ldns_buffer_position(b));
            if (j->leaf == UINT64_MAX) die("%s", "node set append failed");
            ldns_buffer_free(b);
            ldns_rr_free(h);
        }
        n_new = ntodo;
        free(todo);
        free(lm);
        if (abhed_ns_ladder(ns, &ladder)) die("%s", "empty node set");
        if (ladder.nrungs > 60) die("%s", "ladder too large");
        uint8_t lb[ABHED_LADDER_FIXED + 32 * ABHED_MAX_RUNGS];
        size_t lbn = abhed_ladder_encode(&ladder, lb, sizeof lb);
        static uint8_t lsig[ABHED_MLDSA44_SIG_LEN];
        size_t lsl;
        if (abhed_mldsa44_sign(lsig, &lsl, lb, lbn, mtlkey->sk)) die("%s", "ML-DSA-44 ladder signature failed");
        n_mldsa++;
        size_t slen = lbn + 4 + lsl;
        uint8_t *signed_ladder = malloc(slen);
        memcpy(signed_ladder, lb, lbn);
        signed_ladder[lbn] = (uint8_t)(lsl >> 24); signed_ladder[lbn + 1] = (uint8_t)(lsl >> 16);
        signed_ladder[lbn + 2] = (uint8_t)(lsl >> 8); signed_ladder[lbn + 3] = (uint8_t)lsl;
        memcpy(signed_ladder + lbn + 4, lsig, lsl);

        /* state first: a crash after this point leaves a consistent series */
        char tmp[4300];
        snprintf(tmp, sizeof tmp, "%s", nspath);
        if (abhed_ns_save(ns, nspath)) die("cannot write %s", nspath);
        snprintf(tmp, sizeof tmp, "%s.tmp", lmpath);
        FILE *lf = fopen(tmp, "w");
        if (!lf) die("cannot write %s", tmp);
        fprintf(lf, "ABHED-LEAFMAP 1 %s\n", pubhex);
        for (size_t i = 0; i < njobs; i++) {
            job *j = &jobs[i];
            if (j->key->alg != ABHED_ALG_MTL) continue;
            char dg[65]; hexs(dg, j->digest, 32);
            fprintf(lf, "%s %s %llu %u %u\n", j->ident, dg, (unsigned long long)j->leaf, j->inc, j->exp);
        }
        if (fflush(lf) || fsync(fileno(lf)) || fclose(lf)) die("cannot write %s", tmp);
        write_atomic(lmpath, tmp);

        uint8_t *field = malloc(1 + ABHED_COND_FIXED + 16 * ABHED_MAX_SIBS + slen);
        for (size_t i = 0; i < njobs; i++) {
            job *j = &jobs[i];
            if (j->key->alg != ABHED_ALG_MTL) continue;
            abhed_cond cd;
            if (abhed_ns_authpath(ns, j->leaf, &cd)) die("authentication path failed for %s", j->ident);
            size_t p = 0;
            field[p++] = ABHED_T_FULL;
            p += abhed_cond_encode(&cd, field + p, ABHED_COND_FIXED + 16 * ABHED_MAX_SIBS);
            memcpy(field + p, signed_ladder, slen);
            p += slen;
            ldns_rr *h = rrsig_header(j, origin, j->inc, j->exp);
            push_sig(h, field, p);
            ldns_rr_list_push_rr(sigs, h);
        }
        free(field);
        free(signed_ladder);
    }

    /* ---- write the signed zone: SOA first, then canonical order, signatures after their RRset */
    char tmpout[4300];
    snprintf(tmpout, sizeof tmpout, "%s.tmp", opt.out);
    FILE *o = fopen(tmpout, "w");
    if (!o) die("cannot write %s", tmpout);
    fprintf(o, "; signed by abhed-signzone %s at %ld\n", ABHED_VERSION, opt.now);
    ldns_rr_list *all = ldns_rr_list_new();
    for (size_t i = 0; i < njobs; i++)
        for (size_t k = 0; k < ldns_rr_list_rr_count(jobs[i].rrs); k++)
            ldns_rr_list_push_rr(all, ldns_rr_list_rr(jobs[i].rrs, k));
    /* glue and delegation NS records (unsigned) */
    node = ldns_rbtree_first(dz->names);
    while (node != LDNS_RBTREE_NULL) {
        ldns_dnssec_name *nm = (ldns_dnssec_name *)node->data;
        node = ldns_rbtree_next(node);
        int cut = 0;
        for (ldns_dnssec_rrsets *s = nm->rrsets; s; s = s->next)
            if (s->type == LDNS_RR_TYPE_NS && ldns_dname_compare(nm->name, origin) != 0) cut = 1;
        for (ldns_dnssec_rrsets *s = nm->rrsets; s; s = s->next)
            if (nm->is_glue || (cut && s->type != LDNS_RR_TYPE_DS))
                for (ldns_dnssec_rrs *r = s->rrs; r; r = r->next) ldns_rr_list_push_rr(all, r->rr);
    }
    for (size_t i = 0; i < ldns_rr_list_rr_count(sigs); i++) ldns_rr_list_push_rr(all, ldns_rr_list_rr(sigs, i));
    ldns_rr_list_sort(all);
    ldns_rr *soa = NULL;
    for (size_t i = 0; i < ldns_rr_list_rr_count(all); i++)
        if (ldns_rr_get_type(ldns_rr_list_rr(all, i)) == LDNS_RR_TYPE_SOA) soa = ldns_rr_list_rr(all, i);
    if (soa) ldns_rr_print(o, soa);
    for (size_t i = 0; i < ldns_rr_list_rr_count(all); i++)
        if (ldns_rr_list_rr(all, i) != soa) ldns_rr_print(o, ldns_rr_list_rr(all, i));
    if (fflush(o) || fsync(fileno(o)) || fclose(o)) die("cannot write %s", tmpout);
    write_atomic(opt.out, tmpout);

    /* DS records for the parent */
    char dspath[4300];
    snprintf(dspath, sizeof dspath, "%s.ds", opt.out);
    FILE *d = fopen(dspath, "w");
    if (d) {
        for (int i = 0; i < nkeys; i++)
            if (keys[i].flags & 1) {
                ldns_rr *ds = ldns_key_rr2ds(keys[i].dnskey, LDNS_SHA256);
                ldns_rr_print(d, ds);
                ldns_rr_free(ds);
            }
        fclose(d);
    }
    if (!opt.quiet) {
        printf("zone %s: %zu RRsets signed, %zu ML-DSA-44 signatures, %zu ECDSA signatures", opt.origin_s,
               njobs, n_mldsa, n_ecdsa);
        if (mtlkey)
            printf(", MTL: %zu RRsets, %zu new leaves, %llu leaves in series, %u rungs",
                   mtl_jobs, n_new, (unsigned long long)abhed_ns_count(ns), ladder.nrungs);
        printf("\n");
    }
    abhed_ns_free(ns);
    for (int i = 0; i < nkeys; i++) abhed_key_free(&keys[i]);
    return 0;
}
