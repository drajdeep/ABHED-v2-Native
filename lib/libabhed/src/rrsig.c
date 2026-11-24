/*
 * Copyright 2026 Rajdeep Das, IEM-UEM, Kolkata, India
 * SPDX-License-Identifier: Apache-2.0
 * Part of ABHED-v2. See the LICENSE and NOTICE files for terms and attribution.
 */
/* Verification of RRSIG signature fields for algorithm 18 and the MTL algorithm. */
#include <string.h>
#include "abhed/abhed.h"

const char *abhed_result_str(int r)
{
    switch (r) {
    case ABHED_OK: return "ok";
    case ABHED_BOGUS: return "signature does not verify";
    case ABHED_NO_LADDER: return "condensed MTL signature without a cached ladder";
    case ABHED_MALFORMED: return "malformed MTL signature";
    case ABHED_UNSUPPORTED: return "unsupported algorithm or MTL-Type";
    default: return "unknown";
    }
}

size_t abhed_signing_data_signer(const uint8_t *data, size_t datalen, size_t *off)
{
    size_t p = 18;                              /* type, alg, labels, ttl, exp, inc, tag */
    while (p < datalen) {
        uint8_t lab = data[p];
        if (lab > 63) return 0;
        p += 1 + lab;
        if (lab == 0) { *off = 18; return p - 18; }
    }
    return 0;
}

int abhed_verify_rrsig(int alg, const uint8_t *data, size_t datalen,
                       const uint8_t *sig, size_t siglen,
                       const uint8_t *key, size_t keylen,
                       const uint8_t *signer, size_t signerlen)
{
    if (alg == ABHED_ALG_MLDSA44)
        return abhed_mldsa44_verify(key, keylen, data, datalen, sig, siglen) ? ABHED_OK : ABHED_BOGUS;
    if (alg != ABHED_ALG_MTL) return ABHED_UNSUPPORTED;
    if (siglen < 1) return ABHED_MALFORMED;

    abhed_cond c;
    switch (sig[0]) {
    case ABHED_T_FULL: {
        size_t n = abhed_cond_decode(&c, sig + 1, siglen - 1);
        if (!n || c.flags) return ABHED_MALFORMED;
        abhed_ladder l;
        const uint8_t *ls;
        size_t lslen;
        size_t m = abhed_signed_ladder_decode(&l, &ls, &lslen, sig + 1 + n, siglen - 1 - n);
        if (!m || 1 + n + m != siglen) return ABHED_MALFORMED;
        if (!abhed_ladder_well_formed(&l) || memcmp(l.sid, c.sid, ABHED_SID_LEN)) return ABHED_MALFORMED;
        /* cheap hash check first, expensive ML-DSA check second (draft Appendix C) */
        if (!abhed_verify_path(data, datalen, &c, &l)) return ABHED_BOGUS;
        if (abhed_lcache_has(signer, signerlen, &l)) return ABHED_OK;
        uint8_t lb[ABHED_LADDER_FIXED + 32 * ABHED_MAX_RUNGS];
        size_t lbn = abhed_ladder_encode(&l, lb, sizeof lb);
        if (!abhed_mldsa44_verify(key, keylen, lb, lbn, ls, lslen)) return ABHED_BOGUS;
        abhed_lcache_put(signer, signerlen, &l);
        return ABHED_OK;
    }
    case ABHED_T_COND: {
        size_t n = abhed_cond_decode(&c, sig + 1, siglen - 1);
        if (!n || 1 + n != siglen || c.flags) return ABHED_MALFORMED;
        int r = abhed_lcache_verify(signer, signerlen, data, datalen, &c, 0);
        return r == 1 ? ABHED_OK : r == 0 ? ABHED_BOGUS : ABHED_NO_LADDER;
    }
    case ABHED_T_COMPACT: {
        if (!abhed_compact_decode(&c, sig, siglen)) return ABHED_MALFORMED;
        int r = abhed_lcache_verify(signer, signerlen, data, datalen, &c, 1);
        return r == 1 ? ABHED_OK : r == 0 ? ABHED_BOGUS : ABHED_NO_LADDER;
    }
    default:
        return ABHED_UNSUPPORTED;
    }
}
