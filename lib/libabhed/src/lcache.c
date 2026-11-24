/*
 * Copyright 2026 Rajdeep Das, IEM-UEM, Kolkata, India
 * SPDX-License-Identifier: Apache-2.0
 * Part of ABHED-v2. See the LICENSE and NOTICE files for terms and attribution.
 */
/* Process-wide cache of verified ladders, keyed by signer zone. */
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include "abhed/abhed.h"

#define NAME_MAX_WIRE 255
#define NBUCKETS 4096

struct zentry {
    struct zentry *next;                 /* hash chain */
    struct zentry *lru_prev, *lru_next;
    uint8_t name[NAME_MAX_WIRE];
    size_t namelen;
    int nl;
    abhed_ladder *ladders[ABHED_MAX_TAGS]; /* sorted by n, largest first */
};

static pthread_mutex_t mu = PTHREAD_MUTEX_INITIALIZER;
static struct zentry *buckets[NBUCKETS];
static struct zentry *lru_head, *lru_tail;
static size_t nzones, max_zones = 100000;
static struct abhed_lcache_stats st;

static void lower(uint8_t *dst, const uint8_t *src, size_t len)
{
    for (size_t i = 0; i < len; i++)
        dst[i] = (src[i] >= 'A' && src[i] <= 'Z') ? src[i] + 32 : src[i];
}

static uint32_t hname(const uint8_t *n, size_t len)
{
    uint32_t h = 2166136261u;
    for (size_t i = 0; i < len; i++) { h ^= n[i]; h *= 16777619u; }
    return h % NBUCKETS;
}

static void lru_unlink(struct zentry *z)
{
    if (z->lru_prev) z->lru_prev->lru_next = z->lru_next; else lru_head = z->lru_next;
    if (z->lru_next) z->lru_next->lru_prev = z->lru_prev; else lru_tail = z->lru_prev;
    z->lru_prev = z->lru_next = NULL;
}

static void lru_front(struct zentry *z)
{
    z->lru_next = lru_head;
    z->lru_prev = NULL;
    if (lru_head) lru_head->lru_prev = z;
    lru_head = z;
    if (!lru_tail) lru_tail = z;
}

static size_t lbytes(const abhed_ladder *l) { return ABHED_LADDER_FIXED + 32u * l->nrungs; }

static void zfree(struct zentry *z)
{
    for (int i = 0; i < z->nl; i++) { st.ladders--; st.bytes -= lbytes(z->ladders[i]); free(z->ladders[i]); }
    free(z);
}

/* caller holds mu; returns entry or NULL */
static struct zentry *zfind(const uint8_t *name, size_t len, int create)
{
    uint8_t key[NAME_MAX_WIRE];
    if (len == 0 || len > NAME_MAX_WIRE) return NULL;
    lower(key, name, len);
    uint32_t b = hname(key, len);
    for (struct zentry *z = buckets[b]; z; z = z->next)
        if (z->namelen == len && memcmp(z->name, key, len) == 0) {
            lru_unlink(z); lru_front(z);
            return z;
        }
    if (!create) return NULL;
    struct zentry *z = calloc(1, sizeof *z);
    if (!z) return NULL;
    memcpy(z->name, key, len);
    z->namelen = len;
    z->next = buckets[b];
    buckets[b] = z;
    lru_front(z);
    nzones++; st.zones = nzones;
    while (nzones > max_zones && lru_tail && lru_tail != z) {       /* evict LRU zone */
        struct zentry *old = lru_tail;
        lru_unlink(old);
        uint32_t ob = hname(old->name, old->namelen);
        for (struct zentry **pp = &buckets[ob]; *pp; pp = &(*pp)->next)
            if (*pp == old) { *pp = old->next; break; }
        zfree(old);
        nzones--; st.zones = nzones;
    }
    return z;
}

void abhed_lcache_init(size_t mz)
{
    pthread_mutex_lock(&mu);
    if (mz) max_zones = mz;
    pthread_mutex_unlock(&mu);
}

void abhed_lcache_clear(void)
{
    pthread_mutex_lock(&mu);
    for (int b = 0; b < NBUCKETS; b++) {
        struct zentry *z = buckets[b];
        while (z) { struct zentry *n = z->next; zfree(z); z = n; }
        buckets[b] = NULL;
    }
    lru_head = lru_tail = NULL;
    nzones = 0;
    memset(&st, 0, sizeof st);
    pthread_mutex_unlock(&mu);
}

static int same(const abhed_ladder *a, const abhed_ladder *b)
{
    if (a->nrungs != b->nrungs || a->flags != b->flags || memcmp(a->sid, b->sid, ABHED_SID_LEN)) return 0;
    for (int i = 0; i < a->nrungs; i++)
        if (a->rungs[i].left != b->rungs[i].left || a->rungs[i].right != b->rungs[i].right ||
            memcmp(a->rungs[i].hash, b->rungs[i].hash, ABHED_HASH_LEN)) return 0;
    return 1;
}

int abhed_lcache_put(const uint8_t *zone, size_t zonelen, const abhed_ladder *l)
{
    pthread_mutex_lock(&mu);
    struct zentry *z = zfind(zone, zonelen, 1);
    int ok = 0;
    if (z) {
        for (int i = 0; i < z->nl; i++)
            if (same(z->ladders[i], l)) { ok = 1; goto out; }
        abhed_ladder *c = malloc(sizeof *c);
        if (!c) goto out;
        *c = *l;
        if (z->nl == ABHED_MAX_TAGS) {                         /* drop the smallest */
            z->nl--;
            st.ladders--; st.bytes -= lbytes(z->ladders[z->nl]);
            free(z->ladders[z->nl]);
        }
        int pos = z->nl;
        while (pos > 0 && abhed_ladder_n(z->ladders[pos - 1]) < abhed_ladder_n(c)) {
            z->ladders[pos] = z->ladders[pos - 1];
            pos--;
        }
        z->ladders[pos] = c;
        z->nl++;
        st.ladders++; st.bytes += lbytes(c); st.inserts++;
        ok = 1;
    }
out:
    pthread_mutex_unlock(&mu);
    return ok;
}

int abhed_lcache_has(const uint8_t *zone, size_t zonelen, const abhed_ladder *l)
{
    int r = 0;
    pthread_mutex_lock(&mu);
    struct zentry *z = zfind(zone, zonelen, 0);
    if (z)
        for (int i = 0; i < z->nl && !r; i++) r = same(z->ladders[i], l);
    if (r) st.hits++; else st.misses++;
    pthread_mutex_unlock(&mu);
    return r;
}

int abhed_lcache_tags(const uint8_t *zone, size_t zonelen, uint8_t *out, int max)
{
    int k = 0;
    pthread_mutex_lock(&mu);
    struct zentry *z = zfind(zone, zonelen, 0);
    if (z)
        for (int i = 0; i < z->nl && k < max; i++, k++)
            abhed_ladder_tag(z->ladders[i], out + ABHED_TAG_LEN * k);
    pthread_mutex_unlock(&mu);
    return k;
}

/* returns 1 verified, 0 bogus, -1 no usable ladder */
int abhed_lcache_verify(const uint8_t *zone, size_t zonelen, const uint8_t *msg,
                        size_t msglen, abhed_cond *c, int any_sid)
{
    abhed_ladder cand[ABHED_MAX_TAGS];
    int n = 0;
    pthread_mutex_lock(&mu);
    struct zentry *z = zfind(zone, zonelen, 0);
    if (z)
        for (int i = 0; i < z->nl; i++)
            if ((any_sid || !memcmp(z->ladders[i]->sid, c->sid, ABHED_SID_LEN)) &&
                c->leaf < abhed_ladder_n(z->ladders[i]))
                cand[n++] = *z->ladders[i];
    if (n) st.hits++; else st.misses++;
    pthread_mutex_unlock(&mu);
    if (!n) return -1;
    for (int i = 0; i < n; i++) {               /* hashing outside the lock */
        if (any_sid) memcpy(c->sid, cand[i].sid, ABHED_SID_LEN);
        if (abhed_verify_path(msg, msglen, c, &cand[i])) return 1;
    }
    return 0;
}

void abhed_lcache_stats(struct abhed_lcache_stats *s)
{
    pthread_mutex_lock(&mu);
    *s = st;
    pthread_mutex_unlock(&mu);
}
