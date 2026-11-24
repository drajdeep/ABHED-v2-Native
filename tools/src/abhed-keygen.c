/*
 * Copyright 2026 Rajdeep Das, IEM-UEM, Kolkata, India
 * SPDX-License-Identifier: Apache-2.0
 * Part of ABHED-v2. See the LICENSE and NOTICE files for terms and attribution.
 */
/* abhed-keygen: generate a DNSSEC key pair (ECDSAP256SHA256, ML-DSA-44, ML-DSA-44-MTL). */
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <abhed/abhed.h>
#include "keyfile.h"

static void usage(void)
{
    fprintf(stderr,
        "usage: abhed-keygen -a ecdsap256|mldsa44|mtl [-k] [-d dir] zone\n"
        "  -a  algorithm\n  -k  key signing key / CSK (flags 257); default ZSK (flags 256)\n"
        "  -d  output directory (default .)\n"
        "Writes K<zone>+<alg>+<tag>.key and .private and prints the prefix.\n");
    exit(2);
}

int main(int argc, char **argv)
{
    const char *algs = NULL, *dir = ".";
    int ksk = 0, c;
    while ((c = getopt(argc, argv, "a:kd:h")) != -1) {
        if (c == 'a') algs = optarg;
        else if (c == 'k') ksk = 1;
        else if (c == 'd') dir = optarg;
        else usage();
    }
    if (!algs || optind != argc - 1) usage();
    int alg = !strcmp(algs, "ecdsap256") ? ABHED_ALG_ECDSAP256 : !strcmp(algs, "mldsa44") ? ABHED_ALG_MLDSA44
            : !strcmp(algs, "mtl") ? ABHED_ALG_MTL : -1;
    if (alg < 0) usage();
    ldns_rdf *owner = ldns_dname_new_frm_str(argv[optind]);
    if (!owner) { fprintf(stderr, "bad zone name\n"); return 1; }
    ldns_dname2canonical(owner);
    uint16_t flags = ksk ? 257 : 256;
    ldns_rr *rr = NULL;
    char *priv = NULL;
    size_t privlen = 0;
    ldns_key *lk = NULL;

    if (alg == ABHED_ALG_ECDSAP256) {
        lk = ldns_key_new_frm_algorithm(LDNS_SIGN_ECDSAP256SHA256, 256);
        if (!lk) { fprintf(stderr, "ECDSA key generation failed\n"); return 1; }
        ldns_key_set_flags(lk, flags);
        ldns_key_set_pubkey_owner(lk, ldns_rdf_clone(owner));
        rr = ldns_key2rr(lk);
    } else {
        static uint8_t pk[ABHED_MLDSA44_PK_LEN], sk[ABHED_MLDSA44_SK_LEN];
        if (abhed_mldsa44_keygen(pk, sk)) { fprintf(stderr, "ML-DSA-44 key generation failed\n"); return 1; }
        rr = ldns_rr_new();
        ldns_rr_set_type(rr, LDNS_RR_TYPE_DNSKEY);
        ldns_rr_set_owner(rr, ldns_rdf_clone(owner));
        ldns_rr_set_ttl(rr, 3600);
        ldns_rr_push_rdf(rr, ldns_native2rdf_int16(LDNS_RDF_TYPE_INT16, flags));
        ldns_rr_push_rdf(rr, ldns_native2rdf_int8(LDNS_RDF_TYPE_INT8, 3));
        ldns_rr_push_rdf(rr, ldns_native2rdf_int8(LDNS_RDF_TYPE_ALG, (uint8_t)alg));
        ldns_rr_push_rdf(rr, ldns_rdf_new_frm_data(LDNS_RDF_TYPE_B64, sizeof pk, pk));
        ldns_rdf *b = ldns_rdf_new_frm_data(LDNS_RDF_TYPE_B64, sizeof sk, sk);
        priv = ldns_rdf2str(b);
        privlen = strlen(priv);
        memset(ldns_rdf_data(b), 0, sizeof sk);
        ldns_rdf_deep_free(b);
        memset(sk, 0, sizeof sk);
    }
    uint16_t tag = ldns_calc_keytag(rr);
    char *zname = ldns_rdf2str(owner);
    char prefix[4096], path[4200];
    snprintf(prefix, sizeof prefix, "%s/K%s+%03d+%05u", dir, zname, alg, tag);
    mkdir(dir, 0755);

    snprintf(path, sizeof path, "%s.key", prefix);
    FILE *f = fopen(path, "w");
    if (!f) { perror(path); return 1; }
    fprintf(f, "; %s %s for %s, key tag %u\n", ksk ? "KSK/CSK" : "ZSK", abhed_alg_mnemonic(alg), zname, tag);
    ldns_rr_print(f, rr);
    fclose(f);

    snprintf(path, sizeof path, "%s.private", prefix);
    umask(077);
    f = fopen(path, "w");
    if (!f) { perror(path); return 1; }
    if (lk) ldns_key_print(f, lk);
    else fprintf(f, "Private-key-format: v1.3\nAlgorithm: %d (%s)\nPrivateKey: %s\n", alg, abhed_alg_mnemonic(alg), priv);
    fclose(f);
    printf("%s\n", prefix);
    if (priv) { memset(priv, 0, privlen); free(priv); }
    return 0;
}
