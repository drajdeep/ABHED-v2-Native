/*
 * Copyright 2026 Rajdeep Das, IEM-UEM, Kolkata, India
 * SPDX-License-Identifier: Apache-2.0
 * Part of ABHED-v2. See the LICENSE and NOTICE files for terms and attribution.
 *
 * abhed-sigdump: explain the RRSIGs in a zone file or in dig output (reads stdin or files).
 *   dig +dnssec +multi ... | abhed-sigdump
 */
#include <stdio.h>
#include <string.h>
#include <abhed/abhed.h>
#include <ldns/ldns.h>

static void dump(ldns_rr *rr)
{
    ldns_rdf *s = ldns_rr_rrsig_sig(rr);
    if (!s) return;
    int alg = ldns_rdf2native_int8(ldns_rr_rrsig_algorithm(rr));
    char *owner = ldns_rdf2str(ldns_rr_owner(rr));
    char *t = ldns_rr_type2str(ldns_rdf2native_int16(ldns_rr_rrsig_typecovered(rr)));
    const uint8_t *b = ldns_rdf_data(s);
    size_t n = ldns_rdf_size(s);
    printf("%s %s alg %d: %zu-byte signature field", owner, t, alg, n);
    if (alg == ABHED_ALG_MTL && n) {
        abhed_cond c;
        abhed_ladder l;
        const uint8_t *ls;
        size_t lsl, k;
        switch (b[0]) {
        case ABHED_T_FULL:
            k = abhed_cond_decode(&c, b + 1, n - 1);
            if (k && abhed_signed_ladder_decode(&l, &ls, &lsl, b + 1 + k, n - 1 - k))
                printf(", FULL (0x01): leaf %llu, %u siblings, ladder of %llu leaves / %u rungs, %zu-byte ML-DSA-44 signature",
                       (unsigned long long)c.leaf, c.nsibs, (unsigned long long)abhed_ladder_n(&l), l.nrungs, lsl);
            else printf(", FULL (0x01): MALFORMED");
            break;
        case ABHED_T_COND:
            if (abhed_cond_decode(&c, b + 1, n - 1))
                printf(", CONDENSED (0x02): leaf %llu, rung (%llu,%llu), %u siblings", (unsigned long long)c.leaf,
                       (unsigned long long)c.rung_left, (unsigned long long)c.rung_right, c.nsibs);
            else printf(", CONDENSED (0x02): MALFORMED");
            break;
        case ABHED_T_COMPACT:
            if (abhed_compact_decode(&c, b, n))
                printf(", COMPACT (0xF1): leaf %llu, %u siblings", (unsigned long long)c.leaf, c.nsibs);
            else printf(", COMPACT (0xF1): MALFORMED");
            break;
        default: printf(", unknown MTL-Type 0x%02x", b[0]);
        }
    }
    printf("\n");
    free(owner); free(t);
}

static void run(FILE *f)
{
    ldns_rdf *origin = NULL, *prev = NULL;
    uint32_t ttl = 3600;
    int l = 0;
    while (!feof(f)) {
        ldns_rr *rr = NULL;
        ldns_status st = ldns_rr_new_frm_fp_l(&rr, f, &ttl, &origin, &prev, &l);
        if (st != LDNS_STATUS_OK || !rr) continue;     /* comments, $TTL, dig chatter */
        if (ldns_rr_get_type(rr) == LDNS_RR_TYPE_RRSIG) dump(rr);
        ldns_rr_free(rr);
    }
}

int main(int argc, char **argv)
{
    if (argc == 1) run(stdin);
    for (int i = 1; i < argc; i++) {
        FILE *f = fopen(argv[i], "r");
        if (!f) { perror(argv[i]); return 1; }
        run(f);
        fclose(f);
    }
    return 0;
}
