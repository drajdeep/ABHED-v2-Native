/*
 * Copyright 2026 Rajdeep Das, IEM-UEM, Kolkata, India
 * SPDX-License-Identifier: Apache-2.0
 * Part of ABHED-v2. See the LICENSE and NOTICE files for terms and attribution.
 */
/* Keccak-f[1600] and cSHAKE128 (FIPS 202, NIST SP 800-185). Portable, constant-time. */
#include <string.h>
#include "abhed/abhed.h"

#define ROL(x, n) (((x) << (n)) | ((x) >> (64 - (n))))

static const uint64_t RC[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL, 0x8000000080008000ULL,
    0x000000000000808bULL, 0x0000000080000001ULL, 0x8000000080008081ULL, 0x8000000000008009ULL,
    0x000000000000008aULL, 0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL, 0x8000000000008003ULL,
    0x8000000000008002ULL, 0x8000000000000080ULL, 0x000000000000800aULL, 0x800000008000000aULL,
    0x8000000080008081ULL, 0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL};
static const int ROTC[24] = {1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14,
                             27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44};
static const int PILN[24] = {10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4,
                             15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1};

static void keccakf(uint64_t s[25])
{
    uint64_t bc[5], t;
    for (int r = 0; r < 24; r++) {
        for (int i = 0; i < 5; i++)
            bc[i] = s[i] ^ s[i + 5] ^ s[i + 10] ^ s[i + 15] ^ s[i + 20];
        for (int i = 0; i < 5; i++) {
            t = bc[(i + 4) % 5] ^ ROL(bc[(i + 1) % 5], 1);
            for (int j = 0; j < 25; j += 5)
                s[j + i] ^= t;
        }
        t = s[1];
        for (int i = 0; i < 24; i++) {
            int j = PILN[i];
            bc[0] = s[j];
            s[j] = ROL(t, ROTC[i]);
            t = bc[0];
        }
        for (int j = 0; j < 25; j += 5) {
            for (int i = 0; i < 5; i++)
                bc[i] = s[j + i];
            for (int i = 0; i < 5; i++)
                s[j + i] ^= (~bc[(i + 1) % 5]) & bc[(i + 2) % 5];
        }
        s[0] ^= RC[r];
    }
}

#define RATE 168   /* SHAKE128 / cSHAKE128 rate in bytes */

typedef struct { uint64_t s[25]; size_t pos; } kstate;

static void absorb(kstate *k, const uint8_t *in, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        k->s[k->pos / 8] ^= (uint64_t)in[i] << (8 * (k->pos % 8));
        if (++k->pos == RATE) {
            keccakf(k->s);
            k->pos = 0;
        }
    }
}

static void squeeze(kstate *k, uint8_t pad, uint8_t *out, size_t outlen)
{
    k->s[k->pos / 8] ^= (uint64_t)pad << (8 * (k->pos % 8));
    k->s[(RATE - 1) / 8] ^= 0x80ULL << (8 * ((RATE - 1) % 8));
    keccakf(k->s);
    size_t p = 0;
    for (size_t i = 0; i < outlen; i++) {
        if (p == RATE) {
            keccakf(k->s);
            p = 0;
        }
        out[i] = (uint8_t)(k->s[p / 8] >> (8 * (p % 8)));
        p++;
    }
}

/* left_encode(x) from SP 800-185 */
static size_t left_encode(uint8_t out[9], uint64_t x)
{
    uint8_t tmp[8];
    size_t n = 0;
    do { tmp[n++] = (uint8_t)x; x >>= 8; } while (x && n < 8);
    out[0] = (uint8_t)n;
    for (size_t i = 0; i < n; i++)
        out[1 + i] = tmp[n - 1 - i];
    return n + 1;
}

void abhed_cshake128(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen,
                     const uint8_t *custom, size_t customlen)
{
    kstate k;
    memset(&k, 0, sizeof k);
    if (customlen == 0) {                       /* N and S empty: plain SHAKE128 */
        absorb(&k, in, inlen);
        squeeze(&k, 0x1F, out, outlen);
        return;
    }
    uint8_t enc[9];
    size_t total = 0, n;
    n = left_encode(enc, RATE); absorb(&k, enc, n); total += n;          /* bytepad w */
    n = left_encode(enc, 0);    absorb(&k, enc, n); total += n;          /* N = ""    */
    n = left_encode(enc, (uint64_t)customlen * 8); absorb(&k, enc, n); total += n;
    absorb(&k, custom, customlen); total += customlen;
    static const uint8_t zero[RATE] = {0};
    if (total % RATE)
        absorb(&k, zero, RATE - total % RATE);
    absorb(&k, in, inlen);
    squeeze(&k, 0x04, out, outlen);
    memset(&k, 0, sizeof k);
}
