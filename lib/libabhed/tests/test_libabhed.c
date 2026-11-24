/*
 * Copyright 2026 Rajdeep Das, IEM-UEM, Kolkata, India
 * SPDX-License-Identifier: Apache-2.0
 * Unit tests for libabhed. Vectors in vectors.txt come from an independent implementation
 * (pycryptodome cSHAKE128 + the ABHED Python reference used during design).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include "abhed/abhed.h"

static int fails, checks;
#define CHECK(c) do { checks++; if (!(c)) { fails++; fprintf(stderr, "FAIL %s:%d %s\n", __FILE__, __LINE__, #c); } } while (0)

static size_t unhex(const char *s, uint8_t *out, size_t max)
{
    if (!strcmp(s, "-")) return 0;
    size_t n = strlen(s) / 2;
    if (n > max) n = max;
    for (size_t i = 0; i < n; i++) sscanf(s + 2 * i, "%2hhx", &out[i]);
    return n;
}

static void test_vectors(const char *path)
{
    FILE *f = fopen(path, "r");
    CHECK(f != NULL);
    if (!f) return;
    char line[20000], a[64], b[64], c[16000], d[16000];
    static uint8_t buf[8000], exp[8000];
    uint8_t sid[32];
    for (int i = 0; i < 32; i++) sid[i] = (uint8_t)i;
    abhed_nodeset *ns = abhed_ns_new(sid);
    int vec = 0;
    while (fgets(line, sizeof line, f)) {
        if (sscanf(line, "cshake %63s %15999s %15999s", a, c, d) == 3) {
            uint8_t out[16];
            size_t n = unhex(c, buf, sizeof buf);
            abhed_cshake128(out, 16, buf, n, (const uint8_t *)(strcmp(a, "-") ? a : ""), strcmp(a, "-") ? strlen(a) : 0);
            unhex(d, exp, 16);
            CHECK(memcmp(out, exp, 16) == 0); vec++;
        } else if (sscanf(line, "leaf %63s %63s %15999s %15999s", a, b, c, d) == 4) {
            uint8_t rand[16], h[16];
            unhex(b, rand, 16);
            size_t n = unhex(c, buf, sizeof buf);
            abhed_h_leaf(h, sid, rand, strtoull(a, NULL, 10), buf, n);
            unhex(d, exp, 16);
            CHECK(memcmp(h, exp, 16) == 0); vec++;
            CHECK(abhed_ns_push(ns, h, rand) == strtoull(a, NULL, 10));
        } else if (sscanf(line, "ladder %63s %15999s", a, c) == 2) {
            uint64_t n = strtoull(a, NULL, 10);
            abhed_nodeset *part = abhed_ns_new(sid);
            /* rebuild the prefix of n leaves from the full set's level 0 via authpath of leaf data */
            abhed_ladder full; abhed_ns_ladder(ns, &full);
            (void)full;
            abhed_ns_free(part);
            /* compare using a fresh node set built from the vector leaves */
            rewind(f);
            abhed_nodeset *pre = abhed_ns_new(sid);
            char l2[20000];
            while (fgets(l2, sizeof l2, f) && abhed_ns_count(pre) < n) {
                char x[64], y[64], z[16000], w[16000];
                if (sscanf(l2, "leaf %63s %63s %15999s %15999s", x, y, z, w) == 4) {
                    uint8_t r[16], h[16]; unhex(y, r, 16); unhex(w, h, 16);
                    abhed_ns_push(pre, h, r);
                }
            }
            abhed_ladder l; abhed_ns_ladder(pre, &l);
            size_t m = abhed_ladder_encode(&l, buf, sizeof buf);
            size_t e = unhex(c, exp, sizeof exp);
            CHECK(m == e && memcmp(buf, exp, m) == 0); vec++;
            abhed_ns_free(pre);
            /* restore position after this ladder line */
            rewind(f);
            while (fgets(l2, sizeof l2, f) && strcmp(l2, line)) {}
        } else if (sscanf(line, "authpath %63s %15999s", a, c) == 2) {
            abhed_cond cd;
            CHECK(abhed_ns_authpath(ns, strtoull(a, NULL, 10), &cd) == 0);
            size_t m = abhed_cond_encode(&cd, buf, sizeof buf);
            size_t e = unhex(c, exp, sizeof exp);
            CHECK(m == e && memcmp(buf, exp, m) == 0); vec++;
        }
    }
    fclose(f);
    CHECK(vec == 49);
    abhed_ns_free(ns);
}

static void test_tree(void)
{
    abhed_nodeset *ns = abhed_ns_new(NULL);
    char msg[64];
    for (int i = 0; i < 14; i++) { snprintf(msg, sizeof msg, "m%d", i); abhed_ns_append(ns, (uint8_t *)msg, strlen(msg)); }
    abhed_ladder l; abhed_ns_ladder(ns, &l);
    CHECK(l.nrungs == 3 && l.rungs[0].right == 7 && l.rungs[1].left == 8 && l.rungs[1].right == 11 && l.rungs[2].right == 13);
    CHECK(abhed_ladder_well_formed(&l));
    abhed_ladder old = l;
    for (int i = 14; i < 300; i++) { snprintf(msg, sizeof msg, "m%d", i); abhed_ns_append(ns, (uint8_t *)msg, strlen(msg)); }
    abhed_ns_ladder(ns, &l);
    for (uint64_t i = 0; i < 300; i++) {
        abhed_cond c; snprintf(msg, sizeof msg, "m%llu", (unsigned long long)i);
        CHECK(abhed_ns_authpath(ns, i, &c) == 0);
        CHECK(abhed_verify_path((uint8_t *)msg, strlen(msg), &c, &l));
        CHECK(!abhed_verify_path((uint8_t *)msg, strlen(msg) - 1, &c, &l));
        if (c.nsibs) { abhed_cond t = c; t.sibs[0][3] ^= 1; CHECK(!abhed_verify_path((uint8_t *)msg, strlen(msg), &t, &l)); }
        if (i < 14) {                                  /* backward compatibility + trim */
            CHECK(abhed_verify_path((uint8_t *)msg, strlen(msg), &c, &old));
            abhed_cond t = c;
            CHECK(abhed_cond_trim(&t, 14) && t.nsibs < c.nsibs);
            CHECK(abhed_verify_path((uint8_t *)msg, strlen(msg), &t, &old));
            uint8_t w[2000]; size_t n = abhed_compact_encode(&t, w, sizeof w);
            abhed_cond u; CHECK(n == ABHED_COMPACT_FIXED + 16u * t.nsibs && abhed_compact_decode(&u, w, n) == n);
            memcpy(u.sid, old.sid, 32);
            CHECK(abhed_verify_path((uint8_t *)msg, strlen(msg), &u, &old));
        } else {
            CHECK(!abhed_verify_path((uint8_t *)msg, strlen(msg), &c, &old));
        }
    }
    /* state file round trip */
    CHECK(abhed_ns_save(ns, "/tmp/abhed_test.ns") == 0);
    abhed_nodeset *again = abhed_ns_load("/tmp/abhed_test.ns");
    abhed_ladder l2; CHECK(again && abhed_ns_ladder(again, &l2) == 0);
    uint8_t a[4096], b[4096];
    CHECK(abhed_ladder_encode(&l, a, sizeof a) == abhed_ladder_encode(&l2, b, sizeof b) && !memcmp(a, b, abhed_ladder_encode(&l, a, sizeof a)));
    abhed_ns_free(again); abhed_ns_free(ns);
    remove("/tmp/abhed_test.ns");
}

static void test_codecs(void)
{
    uint8_t junk[4096];
    abhed_cond c; abhed_ladder l; const uint8_t *s; size_t sl;
    memset(junk, 0xff, sizeof junk);
    CHECK(abhed_cond_decode(&c, junk, 75) == 0);
    CHECK(abhed_cond_decode(&c, junk, sizeof junk) == 0);        /* sibling count 65535 */
    CHECK(abhed_ladder_decode(&l, junk, sizeof junk) == 0);      /* rung count 65535 */
    CHECK(abhed_signed_ladder_decode(&l, &s, &sl, junk, 10) == 0);
    CHECK(abhed_compact_decode(&c, junk, 25) == 0);
    memset(junk, 0, sizeof junk);
    CHECK(abhed_ladder_decode(&l, junk, 100) == 0);              /* zero rungs */
    uint64_t L[64], R[64];
    CHECK(abhed_rungs_for(0, L, R, 64) == 0);
    CHECK(abhed_rungs_for(UINT64_MAX, L, R, 64) == 64);
}

static void test_rrsig(void)
{
    static uint8_t pk[ABHED_MLDSA44_PK_LEN], sk[ABHED_MLDSA44_SK_LEN], sig[ABHED_MLDSA44_SIG_LEN];
    size_t siglen;
    CHECK(abhed_mldsa44_keygen(pk, sk) == 0);
    /* fake signing data: header(18) + signer "\3iem\3lab\0" + rrset */
    uint8_t data[200] = {0};
    const uint8_t signer[] = {3, 'i', 'e', 'm', 3, 'l', 'a', 'b', 0};
    memcpy(data + 18, signer, sizeof signer);
    memcpy(data + 18 + sizeof signer, "rrset-bytes", 11);
    size_t dlen = 18 + sizeof signer + 11, off, sn = abhed_signing_data_signer(data, dlen, &off);
    CHECK(sn == sizeof signer && off == 18);
    CHECK(abhed_mldsa44_sign(sig, &siglen, data, dlen, sk) == 0);
    CHECK(abhed_verify_rrsig(ABHED_ALG_MLDSA44, data, dlen, sig, siglen, pk, sizeof pk, signer, sizeof signer) == ABHED_OK);
    data[30] ^= 1;
    CHECK(abhed_verify_rrsig(ABHED_ALG_MLDSA44, data, dlen, sig, siglen, pk, sizeof pk, signer, sizeof signer) == ABHED_BOGUS);
    data[30] ^= 1;

    abhed_nodeset *ns = abhed_ns_new(NULL);
    abhed_ns_append(ns, (uint8_t *)"other", 5);
    uint64_t leaf = abhed_ns_append(ns, data, dlen);
    abhed_ns_append(ns, (uint8_t *)"more", 4);
    abhed_ladder l; abhed_ns_ladder(ns, &l);
    uint8_t lb[4096]; size_t lbn = abhed_ladder_encode(&l, lb, sizeof lb);
    CHECK(abhed_mldsa44_sign(sig, &siglen, lb, lbn, sk) == 0);
    abhed_cond c; abhed_ns_authpath(ns, leaf, &c);
    static uint8_t full[8000]; size_t p = 0;
    full[p++] = ABHED_T_FULL;
    p += abhed_cond_encode(&c, full + p, sizeof full - p);
    memcpy(full + p, lb, lbn); p += lbn;
    full[p++] = 0; full[p++] = 0; full[p++] = (uint8_t)(siglen >> 8); full[p++] = (uint8_t)siglen;
    memcpy(full + p, sig, siglen); p += siglen;
    CHECK(p == 1 + 76 + 16u * c.nsibs + 2460 + 32u * l.nrungs);
    uint8_t cond[2000]; size_t cn = 0;
    cond[cn++] = ABHED_T_COND; cn += abhed_cond_encode(&c, cond + cn, sizeof cond - cn);
    abhed_lcache_clear();
    CHECK(abhed_verify_rrsig(ABHED_ALG_MTL, data, dlen, cond, cn, pk, sizeof pk, signer, sizeof signer) == ABHED_NO_LADDER);
    CHECK(abhed_verify_rrsig(ABHED_ALG_MTL, data, dlen, full, p, pk, sizeof pk, signer, sizeof signer) == ABHED_OK);
    struct abhed_lcache_stats st; abhed_lcache_stats(&st);
    CHECK(st.ladders == 1 && st.zones == 1);
    const uint8_t upper[] = {3, 'I', 'E', 'M', 3, 'L', 'A', 'B', 0};
    CHECK(abhed_verify_rrsig(ABHED_ALG_MTL, data, dlen, cond, cn, pk, sizeof pk, upper, sizeof upper) == ABHED_OK);
    uint8_t tags[400]; CHECK(abhed_lcache_tags(signer, sizeof signer, tags, 8) == 1);
    CHECK(!memcmp(tags, l.sid, 32) && tags[39] == 2);
    uint8_t comp[2000]; size_t mn = abhed_compact_encode(&c, comp, sizeof comp);
    CHECK(abhed_verify_rrsig(ABHED_ALG_MTL, data, dlen, comp, mn, pk, sizeof pk, signer, sizeof signer) == ABHED_OK);
    /* other zone must not see the ladder */
    const uint8_t other[] = {3, 'e', 'v', 'l', 0};
    CHECK(abhed_verify_rrsig(ABHED_ALG_MTL, data, dlen, cond, cn, pk, sizeof pk, other, sizeof other) == ABHED_NO_LADDER);
    /* tampering */
    data[33] ^= 1;
    CHECK(abhed_verify_rrsig(ABHED_ALG_MTL, data, dlen, cond, cn, pk, sizeof pk, signer, sizeof signer) == ABHED_BOGUS);
    CHECK(abhed_verify_rrsig(ABHED_ALG_MTL, data, dlen, full, p, pk, sizeof pk, signer, sizeof signer) == ABHED_BOGUS);
    data[33] ^= 1;
    abhed_lcache_clear();
    full[p - 5] ^= 1;                                      /* corrupt the ML-DSA signature */
    CHECK(abhed_verify_rrsig(ABHED_ALG_MTL, data, dlen, full, p, pk, sizeof pk, signer, sizeof signer) == ABHED_BOGUS);
    full[p - 5] ^= 1;
    CHECK(abhed_verify_rrsig(ABHED_ALG_MTL, data, dlen, full, p - 1, pk, sizeof pk, signer, sizeof signer) == ABHED_MALFORMED);
    for (size_t cut = 0; cut < p; cut += 97)               /* truncated inputs never crash */
        CHECK(abhed_verify_rrsig(ABHED_ALG_MTL, data, dlen, full, cut, pk, sizeof pk, signer, sizeof signer) != ABHED_OK);
    abhed_ns_free(ns);
}

static void *worker(void *arg)
{
    uint8_t z[] = {3, 'a', 'b', 'c', 0};
    abhed_ladder l; memset(&l, 0, sizeof l);
    l.nrungs = 1; l.rungs[0].right = (uint64_t)(uintptr_t)arg;
    for (int i = 0; i < 2000; i++) {
        z[1] = (uint8_t)('a' + i % 26);
        abhed_lcache_put(z, sizeof z, &l);
        uint8_t t[400]; abhed_lcache_tags(z, sizeof z, t, 8);
    }
    return NULL;
}

static void test_cache_threads(void)
{
    abhed_lcache_clear();
    abhed_lcache_init(10);
    pthread_t th[8];
    for (long i = 0; i < 8; i++) pthread_create(&th[i], NULL, worker, (void *)(i + 1));
    for (int i = 0; i < 8; i++) pthread_join(th[i], NULL);
    struct abhed_lcache_stats st; abhed_lcache_stats(&st);
    CHECK(st.zones <= 10 && st.ladders <= 80);
    abhed_lcache_clear();
}

int main(int argc, char **argv)
{
    test_vectors(argc > 1 ? argv[1] : "vectors.txt");
    test_tree();
    test_codecs();
    test_rrsig();
    test_cache_threads();
    printf("%d checks, %d failures\n", checks, fails);
    return fails != 0;
}
