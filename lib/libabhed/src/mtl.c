/*
 * Copyright 2026 Rajdeep Das, IEM-UEM, Kolkata, India
 * SPDX-License-Identifier: Apache-2.0
 * Part of ABHED-v2. See the LICENSE and NOTICE files for terms and attribution.
 */
/* MTL hashes, binary rung strategy, wire codecs, path verification. */
#include <string.h>
#include <stdlib.h>
#include "abhed/abhed.h"

static void put64(uint8_t *p, uint64_t v) { for (int i = 7; i >= 0; i--) { p[i] = (uint8_t)v; v >>= 8; } }
static void put16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v; }
static uint64_t get64(const uint8_t *p) { uint64_t v = 0; for (int i = 0; i < 8; i++) v = (v << 8) | p[i]; return v; }
static uint16_t get16(const uint8_t *p) { return (uint16_t)((p[0] << 8) | p[1]); }
static uint32_t get32(const uint8_t *p) { return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3]; }

static const uint8_t C_LEAF[] = {'M', 'T', 'L', 'L', 'E', 'A', 'F'};
static const uint8_t C_INT[] = {'M', 'T', 'L', 'I', 'N', 'T'};

/* cSHAKE over a message assembled from a prefix and a (possibly long) tail, without copying
 * the tail: the function absorbs prefix then tail. Implemented with a small stack buffer for
 * short messages and a heap buffer otherwise. */
void abhed_h_leaf(uint8_t out[ABHED_HASH_LEN], const uint8_t sid[ABHED_SID_LEN],
                  const uint8_t rand[ABHED_RAND_LEN], uint64_t index,
                  const uint8_t *msg, size_t msglen)
{
    uint8_t stackbuf[1024];
    size_t pre = ABHED_SID_LEN + ABHED_RAND_LEN + 8 + 1, len = pre + msglen;
    uint8_t *b = len <= sizeof stackbuf ? stackbuf : malloc(len);
    if (!b) { memset(out, 0, ABHED_HASH_LEN); return; }
    memcpy(b, sid, ABHED_SID_LEN);
    memcpy(b + ABHED_SID_LEN, rand, ABHED_RAND_LEN);
    put64(b + ABHED_SID_LEN + ABHED_RAND_LEN, index);
    b[pre - 1] = 0x00;                         /* len(ctx_msg) = 0 */
    if (msglen) memcpy(b + pre, msg, msglen);
    abhed_cshake128(out, ABHED_HASH_LEN, b, len, C_LEAF, sizeof C_LEAF);
    if (b != stackbuf) free(b);
}

void abhed_h_int(uint8_t out[ABHED_HASH_LEN], const uint8_t sid[ABHED_SID_LEN],
                 uint64_t left, uint64_t right,
                 const uint8_t hl[ABHED_HASH_LEN], const uint8_t hr[ABHED_HASH_LEN])
{
    uint8_t b[ABHED_SID_LEN + 16 + 2 * ABHED_HASH_LEN];
    memcpy(b, sid, ABHED_SID_LEN);
    put64(b + 32, left);
    put64(b + 40, right);
    memcpy(b + 48, hl, ABHED_HASH_LEN);
    memcpy(b + 64, hr, ABHED_HASH_LEN);
    abhed_cshake128(out, ABHED_HASH_LEN, b, sizeof b, C_INT, sizeof C_INT);
}

int abhed_rungs_for(uint64_t n, uint64_t lefts[], uint64_t rights[], int max)
{
    int k = 0;
    uint64_t left = 0;
    for (int bit = 63; bit >= 0 && n; bit--) {
        uint64_t size = 1ULL << bit;
        if (!(n & size)) continue;
        if (k >= max) return -1;
        lefts[k] = left;
        rights[k] = left + size - 1;
        left += size;
        n -= size;
        k++;
    }
    return k;
}

uint64_t abhed_ladder_n(const abhed_ladder *l)
{
    return l->nrungs ? l->rungs[l->nrungs - 1].right + 1 : 0;
}

int abhed_ladder_well_formed(const abhed_ladder *l)
{
    uint64_t L[ABHED_MAX_RUNGS], R[ABHED_MAX_RUNGS];
    if (l->flags != 0 || l->nrungs == 0) return 0;
    int k = abhed_rungs_for(abhed_ladder_n(l), L, R, ABHED_MAX_RUNGS);
    if (k != l->nrungs) return 0;
    for (int i = 0; i < k; i++)
        if (l->rungs[i].left != L[i] || l->rungs[i].right != R[i]) return 0;
    return 1;
}

void abhed_ladder_tag(const abhed_ladder *l, uint8_t tag[ABHED_TAG_LEN])
{
    memcpy(tag, l->sid, ABHED_SID_LEN);
    put64(tag + ABHED_SID_LEN, abhed_ladder_n(l) - 1);
}

size_t abhed_ladder_encode(const abhed_ladder *l, uint8_t *out, size_t outlen)
{
    size_t need = ABHED_LADDER_FIXED + 32u * l->nrungs;
    if (outlen < need) return 0;
    put16(out, l->flags);
    memcpy(out + 2, l->sid, ABHED_SID_LEN);
    put16(out + 34, l->nrungs);
    uint8_t *p = out + 36;
    for (int i = 0; i < l->nrungs; i++, p += 32) {
        put64(p, l->rungs[i].left);
        put64(p + 8, l->rungs[i].right);
        memcpy(p + 16, l->rungs[i].hash, ABHED_HASH_LEN);
    }
    return need;
}

size_t abhed_ladder_decode(abhed_ladder *l, const uint8_t *in, size_t inlen)
{
    if (inlen < ABHED_LADDER_FIXED) return 0;
    l->flags = get16(in);
    memcpy(l->sid, in + 2, ABHED_SID_LEN);
    l->nrungs = get16(in + 34);
    if (l->nrungs == 0 || l->nrungs > ABHED_MAX_RUNGS) return 0;
    size_t need = ABHED_LADDER_FIXED + 32u * l->nrungs;
    if (inlen < need) return 0;
    const uint8_t *p = in + 36;
    for (int i = 0; i < l->nrungs; i++, p += 32) {
        l->rungs[i].left = get64(p);
        l->rungs[i].right = get64(p + 8);
        memcpy(l->rungs[i].hash, p + 16, ABHED_HASH_LEN);
    }
    return need;
}

size_t abhed_signed_ladder_decode(abhed_ladder *l, const uint8_t **sig, size_t *siglen,
                                  const uint8_t *in, size_t inlen)
{
    size_t n = abhed_ladder_decode(l, in, inlen);
    if (!n || inlen - n < 4) return 0;
    uint32_t sl = get32(in + n);
    if (sl == 0 || sl > inlen - n - 4) return 0;
    *sig = in + n + 4;
    *siglen = sl;
    return n + 4 + sl;
}

size_t abhed_cond_len(const abhed_cond *c) { return ABHED_COND_FIXED + 16u * c->nsibs; }

size_t abhed_cond_encode(const abhed_cond *c, uint8_t *out, size_t outlen)
{
    size_t need = abhed_cond_len(c);
    if (outlen < need) return 0;
    put16(out, c->flags);
    memcpy(out + 2, c->sid, ABHED_SID_LEN);
    memcpy(out + 34, c->rand, ABHED_RAND_LEN);
    put64(out + 50, c->leaf);
    put64(out + 58, c->rung_left);
    put64(out + 66, c->rung_right);
    put16(out + 74, c->nsibs);
    for (int i = 0; i < c->nsibs; i++)
        memcpy(out + 76 + 16 * i, c->sibs[i], ABHED_HASH_LEN);
    return need;
}

size_t abhed_cond_decode(abhed_cond *c, const uint8_t *in, size_t inlen)
{
    if (inlen < ABHED_COND_FIXED) return 0;
    c->flags = get16(in);
    memcpy(c->sid, in + 2, ABHED_SID_LEN);
    memcpy(c->rand, in + 34, ABHED_RAND_LEN);
    c->leaf = get64(in + 50);
    c->rung_left = get64(in + 58);
    c->rung_right = get64(in + 66);
    c->nsibs = get16(in + 74);
    if (c->nsibs > ABHED_MAX_SIBS || inlen < abhed_cond_len(c)) return 0;
    for (int i = 0; i < c->nsibs; i++)
        memcpy(c->sibs[i], in + 76 + 16 * i, ABHED_HASH_LEN);
    return abhed_cond_len(c);
}

size_t abhed_compact_encode(const abhed_cond *c, uint8_t *out, size_t outlen)
{
    size_t need = ABHED_COMPACT_FIXED + 16u * c->nsibs;
    if (outlen < need || c->nsibs > 255) return 0;
    out[0] = ABHED_T_COMPACT;
    memcpy(out + 1, c->rand, ABHED_RAND_LEN);
    put64(out + 17, c->leaf);
    out[25] = (uint8_t)c->nsibs;
    for (int i = 0; i < c->nsibs; i++)
        memcpy(out + 26 + 16 * i, c->sibs[i], ABHED_HASH_LEN);
    return need;
}

size_t abhed_compact_decode(abhed_cond *c, const uint8_t *in, size_t inlen)
{
    if (inlen < ABHED_COMPACT_FIXED || in[0] != ABHED_T_COMPACT) return 0;
    memset(c, 0, offsetof(abhed_cond, sibs));
    memcpy(c->rand, in + 1, ABHED_RAND_LEN);
    c->leaf = get64(in + 17);
    c->nsibs = in[25];
    size_t need = ABHED_COMPACT_FIXED + 16u * c->nsibs;
    if (c->nsibs > ABHED_MAX_SIBS || inlen != need) return 0;
    for (int i = 0; i < c->nsibs; i++)
        memcpy(c->sibs[i], in + 26 + 16 * i, ABHED_HASH_LEN);
    return need;
}

int abhed_cond_trim(abhed_cond *c, uint64_t n)
{
    uint64_t L[ABHED_MAX_RUNGS], R[ABHED_MAX_RUNGS];
    int k = abhed_rungs_for(n, L, R, ABHED_MAX_RUNGS);
    for (int i = 0; i < k; i++) {
        if (c->leaf < L[i] || c->leaf > R[i]) continue;
        int height = 0;
        for (uint64_t size = R[i] - L[i] + 1; size > 1; size >>= 1) height++;
        if (height > c->nsibs) return 0;
        c->nsibs = (uint16_t)height;
        c->rung_left = L[i];
        c->rung_right = R[i];
        return 1;
    }
    return 0;
}

/* Constant-time compare of two hashes. */
static int heq(const uint8_t *a, const uint8_t *b)
{
    uint8_t d = 0;
    for (int i = 0; i < ABHED_HASH_LEN; i++) d |= a[i] ^ b[i];
    return d == 0;
}

static const abhed_rung *find_rung(const abhed_ladder *l, uint64_t left, uint64_t right)
{
    for (int i = 0; i < l->nrungs; i++)
        if (l->rungs[i].left == left && l->rungs[i].right == right) return &l->rungs[i];
    return NULL;
}

int abhed_verify_path(const uint8_t *msg, size_t msglen, const abhed_cond *c,
                      const abhed_ladder *ladder)
{
    if (memcmp(c->sid, ladder->sid, ABHED_SID_LEN) != 0) return 0;
    if (c->leaf >= abhed_ladder_n(ladder)) return 0;
    uint8_t h[ABHED_HASH_LEN];
    abhed_h_leaf(h, c->sid, c->rand, c->leaf, msg, msglen);
    uint64_t l = c->leaf, r = c->leaf;
    for (int i = 0;; i++) {
        const abhed_rung *rg = find_rung(ladder, l, r);
        if (rg) return heq(rg->hash, h);
        if (i >= c->nsibs) return 0;
        uint64_t size = r - l + 1;
        if (size > (1ULL << 62)) return 0;
        if ((l / size) % 2 == 0) {
            abhed_h_int(h, c->sid, l, r + size, h, c->sibs[i]);
            r += size;
        } else {
            abhed_h_int(h, c->sid, l - size, r, c->sibs[i], h);
            l -= size;
        }
    }
}
