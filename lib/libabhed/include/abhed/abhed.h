/*
 * Copyright 2026 Rajdeep Das, IEM-UEM, Kolkata, India
 * SPDX-License-Identifier: Apache-2.0
 * Part of ABHED-v2. See the LICENSE and NOTICE files for terms and attribution.
 *
 * libabhed: ML-DSA-44 and ML-DSA-44-MTL-SHAKE-128 for DNSSEC.
 *
 *   draft-kaizer-dnsop-ml-dsa-mtl-dnssec-03            base format (MTL-Type 0x01)
 *   draft-hdong-dnsop-ml-dsa-mtl-dnssec-sigtag-ext-01  SigTag, condensed (MTL-Type 0x02)
 *   draft-westerbaan-dnssec-mldsa-04                    ML-DSA-44, algorithm 18
 *   ABHED compact condensed signature                   MTL-Type 0xF1 (private use)
 *
 * All parsing functions are bounds-checked and never read past the given length.
 * Nothing in this library allocates on the verify path except the ladder cache.
 */
#ifndef ABHED_H
#define ABHED_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ABHED_VERSION "2.1.1"

/* ------------------------------------------------------------------ code points */
#define ABHED_ALG_ECDSAP256   13
#define ABHED_ALG_MLDSA44     18            /* IANA-assigned */
#ifndef ABHED_ALG_MTL
#define ABHED_ALG_MTL         244           /* TBD in the draft; Private Use range proposal */
#endif
#ifndef ABHED_OPT_SIGTAG
#define ABHED_OPT_SIGTAG      65001         /* TBD in the draft; RFC 6891 local use range */
#endif
#ifndef ABHED_OPT_ABHED
#define ABHED_OPT_ABHED       65002
#endif
#define ABHED_F_TRIM          0x01          /* client accepts paths trimmed to its ladder */
#define ABHED_F_COMPACT       0x02          /* client accepts MTL-Type 0xF1 */

#define ABHED_T_FULL          0x01
#define ABHED_T_COND          0x02
#define ABHED_T_COMPACT       0xF1

/* ------------------------------------------------------------------ sizes */
#define ABHED_HASH_LEN        16
#define ABHED_SID_LEN         32
#define ABHED_RAND_LEN        16
#define ABHED_TAG_LEN         40            /* SID | right index */
#define ABHED_MAX_TAGS        8
#define ABHED_MAX_SIBS        64
#define ABHED_MAX_RUNGS       64
#define ABHED_MLDSA44_PK_LEN  1312
#define ABHED_MLDSA44_SK_LEN  2560
#define ABHED_MLDSA44_SIG_LEN 2420
#define ABHED_COND_FIXED      76            /* + 16 per sibling */
#define ABHED_COMPACT_FIXED   26            /* type(1) rand(16) leaf(8) count(1) + 16 per sibling */
#define ABHED_LADDER_FIXED    36            /* flags(2) sid(32) count(2) + 32 per rung */

/* ------------------------------------------------------------------ hashing */
/* cSHAKE128 (NIST SP 800-185) with empty function name N. */
void abhed_cshake128(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen,
                     const uint8_t *custom, size_t customlen);
void abhed_h_leaf(uint8_t out[ABHED_HASH_LEN], const uint8_t sid[ABHED_SID_LEN],
                  const uint8_t rand[ABHED_RAND_LEN], uint64_t index,
                  const uint8_t *msg, size_t msglen);
void abhed_h_int(uint8_t out[ABHED_HASH_LEN], const uint8_t sid[ABHED_SID_LEN],
                 uint64_t left, uint64_t right,
                 const uint8_t hl[ABHED_HASH_LEN], const uint8_t hr[ABHED_HASH_LEN]);

/* ------------------------------------------------------------------ structures */
typedef struct {
    uint64_t left, right;
    uint8_t  hash[ABHED_HASH_LEN];
} abhed_rung;

typedef struct {
    uint16_t   flags;
    uint8_t    sid[ABHED_SID_LEN];
    uint16_t   nrungs;
    abhed_rung rungs[ABHED_MAX_RUNGS];
} abhed_ladder;

typedef struct {
    uint16_t flags;
    uint8_t  sid[ABHED_SID_LEN];
    uint8_t  rand[ABHED_RAND_LEN];
    uint64_t leaf, rung_left, rung_right;
    uint16_t nsibs;
    uint8_t  sibs[ABHED_MAX_SIBS][ABHED_HASH_LEN];
} abhed_cond;

/* Number of leaves covered by a ladder (right index of the last rung + 1). */
uint64_t abhed_ladder_n(const abhed_ladder *l);
/* Fill rungs' index pairs for the binary rung strategy (hashes untouched). Returns count. */
int  abhed_rungs_for(uint64_t n, uint64_t lefts[], uint64_t rights[], int max);
/* 1 if flags are zero and the rung layout is exactly the binary strategy for its size. */
int  abhed_ladder_well_formed(const abhed_ladder *l);
void abhed_ladder_tag(const abhed_ladder *l, uint8_t tag[ABHED_TAG_LEN]);

/* ------------------------------------------------------------------ wire codecs
 * encode_*: return bytes written, or 0 if out is too small.
 * decode_*: return bytes consumed, or 0 on any malformation.                      */
size_t abhed_ladder_encode(const abhed_ladder *l, uint8_t *out, size_t outlen);
size_t abhed_ladder_decode(abhed_ladder *l, const uint8_t *in, size_t inlen);
size_t abhed_cond_encode(const abhed_cond *c, uint8_t *out, size_t outlen);
size_t abhed_cond_decode(abhed_cond *c, const uint8_t *in, size_t inlen);
size_t abhed_cond_len(const abhed_cond *c);
/* Signed ladder = ladder | siglen(4) | sig. *sig points into in. */
size_t abhed_signed_ladder_decode(abhed_ladder *l, const uint8_t **sig, size_t *siglen,
                                  const uint8_t *in, size_t inlen);
/* Compact 0xF1 form: type | rand | leaf | count | sibs (SID and rung are implied). */
size_t abhed_compact_encode(const abhed_cond *c, uint8_t *out, size_t outlen);
size_t abhed_compact_decode(abhed_cond *c, const uint8_t *in, size_t inlen);
/* Cut a path so it ends at the rung covering c->leaf in a ladder of n leaves. 0 if not covered. */
int  abhed_cond_trim(abhed_cond *c, uint64_t n);

/* ------------------------------------------------------------------ verification
 * 1 if the authentication path proves msg against ANY rung of ladder (backward compatible).
 * Uses c->sid, c->rand, c->leaf, c->sibs; rung indices in c are not trusted.           */
int abhed_verify_path(const uint8_t *msg, size_t msglen, const abhed_cond *c,
                      const abhed_ladder *ladder);

/* ------------------------------------------------------------------ ML-DSA-44 (liboqs) */
int abhed_mldsa44_keygen(uint8_t pk[ABHED_MLDSA44_PK_LEN], uint8_t sk[ABHED_MLDSA44_SK_LEN]);
int abhed_mldsa44_sign(uint8_t sig[ABHED_MLDSA44_SIG_LEN], size_t *siglen,
                       const uint8_t *msg, size_t msglen, const uint8_t *sk);
int abhed_mldsa44_verify(const uint8_t *pk, size_t pklen, const uint8_t *msg, size_t msglen,
                         const uint8_t *sig, size_t siglen);

/* ------------------------------------------------------------------ RRSIG verification
 * Verify one RRSIG signature field for algorithm 18 or ABHED_ALG_MTL.
 *   data    : RFC 4034 3.1.8.1 signing data (RRSIG RDATA without signature | canonical RRset)
 *   signer  : signer name, uncompressed wire format (any case)
 * For MTL, verified ladders are stored in, and condensed signatures checked against, the
 * process-wide ladder cache. Thread-safe.                                                */
enum abhed_result {
    ABHED_OK = 0,
    ABHED_BOGUS = 1,          /* signature does not verify */
    ABHED_NO_LADDER = 2,      /* condensed signature, no cached ladder: refetch without SigTag */
    ABHED_MALFORMED = 3,
    ABHED_UNSUPPORTED = 4
};
int abhed_verify_rrsig(int alg, const uint8_t *data, size_t datalen,
                       const uint8_t *sig, size_t siglen,
                       const uint8_t *key, size_t keylen,
                       const uint8_t *signer, size_t signerlen);
const char *abhed_result_str(int r);
/* Offset of the signer name in RFC 4034 signing data and its length, or 0 on error. */
size_t abhed_signing_data_signer(const uint8_t *data, size_t datalen, size_t *off);

/* ------------------------------------------------------------------ ladder cache
 * Process-wide, keyed by signer zone (case-insensitive wire name), up to ABHED_MAX_TAGS
 * ladders per zone (largest first), bounded number of zones (LRU).                    */
void abhed_lcache_init(size_t max_zones);
void abhed_lcache_clear(void);
/* Write up to max SigTags for zone into out (40 bytes each). Returns the count. */
int  abhed_lcache_tags(const uint8_t *zone, size_t zonelen, uint8_t *out, int max);
int  abhed_lcache_put(const uint8_t *zone, size_t zonelen, const abhed_ladder *l);
/* 1 if an identical ladder (same tag and bytes) is cached for zone. */
int  abhed_lcache_has(const uint8_t *zone, size_t zonelen, const abhed_ladder *l);
/* 1 if c verifies against any cached ladder of zone (matching SID; compact: any SID). */
int  abhed_lcache_verify(const uint8_t *zone, size_t zonelen, const uint8_t *msg,
                         size_t msglen, abhed_cond *c, int any_sid);
struct abhed_lcache_stats { uint64_t zones, ladders, bytes, hits, misses, inserts; };
void abhed_lcache_stats(struct abhed_lcache_stats *s);

/* ------------------------------------------------------------------ node set (signer)
 * Append-only MTL node set. Stateful: callers must persist it and never reuse a SID.  */
typedef struct abhed_nodeset abhed_nodeset;
abhed_nodeset *abhed_ns_new(const uint8_t sid[ABHED_SID_LEN]);   /* sid NULL: random */
void     abhed_ns_free(abhed_nodeset *ns);
uint64_t abhed_ns_count(const abhed_nodeset *ns);
const uint8_t *abhed_ns_sid(const abhed_nodeset *ns);
/* Append a message (random randomizer). Returns leaf index, or UINT64_MAX on error. */
uint64_t abhed_ns_append(abhed_nodeset *ns, const uint8_t *msg, size_t msglen);
/* Append a precomputed leaf hash with its randomizer (used when loading state). */
uint64_t abhed_ns_push(abhed_nodeset *ns, const uint8_t leafhash[ABHED_HASH_LEN],
                       const uint8_t rand[ABHED_RAND_LEN]);
int  abhed_ns_ladder(const abhed_nodeset *ns, abhed_ladder *out);
int  abhed_ns_authpath(const abhed_nodeset *ns, uint64_t leaf, abhed_cond *out);
/* State file: "ABHEDNS1" | sid | count(8) | (leafhash | rand) * count. Atomic write. */
int  abhed_ns_save(const abhed_nodeset *ns, const char *path);
abhed_nodeset *abhed_ns_load(const char *path);

/* Fill buf with len bytes from the OS random number generator. 0 on success. */
int abhed_random(uint8_t *buf, size_t len);

#ifdef __cplusplus
}
#endif
#endif
