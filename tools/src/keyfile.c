/*
 * Copyright 2026 Rajdeep Das, IEM-UEM, Kolkata, India
 * SPDX-License-Identifier: Apache-2.0
 * Part of ABHED-v2. See the LICENSE and NOTICE files for terms and attribution.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <abhed/abhed.h>
#include "keyfile.h"

const char *abhed_alg_mnemonic(int alg)
{
    switch (alg) {
    case ABHED_ALG_ECDSAP256: return "ECDSAP256SHA256";
    case ABHED_ALG_MLDSA44: return "MLDSA44";
    case ABHED_ALG_MTL: return "MLDSA44MTLSHAKE128";
    default: return "UNKNOWN";
    }
}

static char *slurp(const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    rewind(f);
    char *b = malloc((size_t)n + 1);
    if (b && fread(b, 1, (size_t)n, f) != (size_t)n) { free(b); b = NULL; }
    if (b) b[n] = 0;
    fclose(f);
    return b;
}

int abhed_key_load(abhed_key *k, const char *prefix)
{
    memset(k, 0, sizeof *k);
    snprintf(k->path, sizeof k->path, "%s", prefix);
    char p[4200];
    snprintf(p, sizeof p, "%s.key", prefix);
    FILE *f = fopen(p, "r");
    if (!f) { fprintf(stderr, "cannot open %s\n", p); return -1; }
    ldns_rr *rr = NULL;
    for (;;) {                                         /* skip comments, take first RR */
        ldns_status s = ldns_rr_new_frm_fp(&rr, f, NULL, NULL, NULL);
        if (s == LDNS_STATUS_SYNTAX_EMPTY || s == LDNS_STATUS_SYNTAX_TTL || s == LDNS_STATUS_SYNTAX_ORIGIN) continue;
        if (s != LDNS_STATUS_OK) { fclose(f); fprintf(stderr, "%s: %s\n", p, ldns_get_errorstr_by_id(s)); return -1; }
        break;
    }
    fclose(f);
    if (ldns_rr_get_type(rr) != LDNS_RR_TYPE_DNSKEY) { ldns_rr_free(rr); return -1; }
    k->dnskey = rr;
    k->alg = ldns_rdf2native_int8(ldns_rr_dnskey_algorithm(rr));
    k->flags = ldns_rdf2native_int16(ldns_rr_dnskey_flags(rr));
    k->tag = ldns_calc_keytag(rr);
    snprintf(p, sizeof p, "%s.private", prefix);
    if (k->alg == ABHED_ALG_ECDSAP256) {
        f = fopen(p, "r");
        if (!f || ldns_key_new_frm_fp(&k->ldnskey, f) != LDNS_STATUS_OK) {
            if (f) fclose(f);
            fprintf(stderr, "%s: cannot read ECDSA private key\n", p);
            return -1;
        }
        fclose(f);
        ldns_key_set_flags(k->ldnskey, k->flags);
        ldns_key_set_pubkey_owner(k->ldnskey, ldns_rdf_clone(ldns_rr_owner(rr)));
        return 0;
    }
    if (k->alg != ABHED_ALG_MLDSA44 && k->alg != ABHED_ALG_MTL) {
        fprintf(stderr, "%s: unsupported algorithm %d\n", prefix, k->alg);
        return -1;
    }
    char *txt = slurp(p);
    char *line = txt ? strstr(txt, "PrivateKey:") : NULL;
    if (!line) { free(txt); fprintf(stderr, "%s: no PrivateKey line\n", p); return -1; }
    line += strlen("PrivateKey:");
    while (*line == ' ') line++;
    char *end = strpbrk(line, "\r\n");
    if (end) *end = 0;
    ldns_rdf *b = NULL;
    ldns_status st = ldns_str2rdf_b64(&b, line);
    memset(txt, 0, strlen(txt));
    free(txt);
    if (st != LDNS_STATUS_OK || ldns_rdf_size(b) != ABHED_MLDSA44_SK_LEN) {
        if (b) ldns_rdf_deep_free(b);
        fprintf(stderr, "%s: bad ML-DSA-44 private key\n", p);
        return -1;
    }
    k->sklen = ldns_rdf_size(b);
    k->sk = malloc(k->sklen);
    memcpy(k->sk, ldns_rdf_data(b), k->sklen);
    memset(ldns_rdf_data(b), 0, k->sklen);
    ldns_rdf_deep_free(b);
    return 0;
}

void abhed_key_free(abhed_key *k)
{
    if (k->sk) { memset(k->sk, 0, k->sklen); free(k->sk); }
    if (k->dnskey) ldns_rr_free(k->dnskey);
    if (k->ldnskey) ldns_key_deep_free(k->ldnskey);
    memset(k, 0, sizeof *k);
}
