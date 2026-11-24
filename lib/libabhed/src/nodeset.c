/*
 * Copyright 2026 Rajdeep Das, IEM-UEM, Kolkata, India
 * SPDX-License-Identifier: Apache-2.0
 * Part of ABHED-v2. See the LICENSE and NOTICE files for terms and attribution.
 */
/* Append-only MTL node set for signers, with atomic state files. */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <unistd.h>
#include "abhed/abhed.h"

/* level k holds the complete subtrees of size 2^k: node j covers [j*2^k, (j+1)*2^k - 1] */
struct abhed_nodeset {
    uint8_t sid[ABHED_SID_LEN];
    uint64_t count;
    uint8_t *rands;                      /* count * 16 */
    uint8_t *levels[64];                 /* levels[k]: (count >> k) * 16 */
    uint64_t cap[64];
    uint64_t rand_cap;
};

int abhed_random(uint8_t *buf, size_t len)
{
    while (len) {
        ssize_t r = getrandom(buf, len, 0);
        if (r < 0) { if (errno == EINTR) continue; return -1; }
        buf += r; len -= (size_t)r;
    }
    return 0;
}

abhed_nodeset *abhed_ns_new(const uint8_t sid[ABHED_SID_LEN])
{
    abhed_nodeset *ns = calloc(1, sizeof *ns);
    if (!ns) return NULL;
    if (sid) memcpy(ns->sid, sid, ABHED_SID_LEN);
    else if (abhed_random(ns->sid, ABHED_SID_LEN)) { free(ns); return NULL; }
    return ns;
}

void abhed_ns_free(abhed_nodeset *ns)
{
    if (!ns) return;
    free(ns->rands);
    for (int k = 0; k < 64; k++) free(ns->levels[k]);
    free(ns);
}

uint64_t abhed_ns_count(const abhed_nodeset *ns) { return ns->count; }
const uint8_t *abhed_ns_sid(const abhed_nodeset *ns) { return ns->sid; }

static int grow(uint8_t **p, uint64_t *cap, uint64_t need, size_t elem)
{
    if (need <= *cap) return 0;
    uint64_t nc = *cap ? *cap * 2 : 1024;
    while (nc < need) nc *= 2;
    uint8_t *q = realloc(*p, nc * elem);
    if (!q) return -1;
    *p = q; *cap = nc;
    return 0;
}

uint64_t abhed_ns_push(abhed_nodeset *ns, const uint8_t leafhash[ABHED_HASH_LEN],
                       const uint8_t rand[ABHED_RAND_LEN])
{
    uint64_t i = ns->count;
    if (grow(&ns->rands, &ns->rand_cap, i + 1, ABHED_RAND_LEN)) return UINT64_MAX;
    memcpy(ns->rands + 16 * i, rand, ABHED_RAND_LEN);
    if (grow(&ns->levels[0], &ns->cap[0], i + 1, ABHED_HASH_LEN)) return UINT64_MAX;
    memcpy(ns->levels[0] + 16 * i, leafhash, ABHED_HASH_LEN);
    /* combine while the new node is a right child */
    uint64_t j = i;
    for (int k = 0; k < 62 && (j & 1); k++, j >>= 1) {
        uint64_t parent = j >> 1, size = 1ULL << k;
        if (grow(&ns->levels[k + 1], &ns->cap[k + 1], parent + 1, ABHED_HASH_LEN)) return UINT64_MAX;
        uint64_t left = parent * 2 * size;
        abhed_h_int(ns->levels[k + 1] + 16 * parent, ns->sid, left, left + 2 * size - 1,
                    ns->levels[k] + 16 * (j - 1), ns->levels[k] + 16 * j);
    }
    ns->count = i + 1;
    return i;
}

uint64_t abhed_ns_append(abhed_nodeset *ns, const uint8_t *msg, size_t msglen)
{
    uint8_t rand[ABHED_RAND_LEN], h[ABHED_HASH_LEN];
    if (abhed_random(rand, sizeof rand)) return UINT64_MAX;
    abhed_h_leaf(h, ns->sid, rand, ns->count, msg, msglen);
    return abhed_ns_push(ns, h, rand);
}

static const uint8_t *node(const abhed_nodeset *ns, uint64_t left, uint64_t right)
{
    uint64_t size = right - left + 1;
    int k = 0;
    while ((1ULL << k) < size) k++;
    return ns->levels[k] + 16 * (left >> k);
}

int abhed_ns_ladder(const abhed_nodeset *ns, abhed_ladder *out)
{
    uint64_t L[ABHED_MAX_RUNGS], R[ABHED_MAX_RUNGS];
    int k = abhed_rungs_for(ns->count, L, R, ABHED_MAX_RUNGS);
    if (k <= 0) return -1;
    memset(out, 0, sizeof *out);
    memcpy(out->sid, ns->sid, ABHED_SID_LEN);
    out->nrungs = (uint16_t)k;
    for (int i = 0; i < k; i++) {
        out->rungs[i].left = L[i];
        out->rungs[i].right = R[i];
        memcpy(out->rungs[i].hash, node(ns, L[i], R[i]), ABHED_HASH_LEN);
    }
    return 0;
}

int abhed_ns_authpath(const abhed_nodeset *ns, uint64_t leaf, abhed_cond *out)
{
    if (leaf >= ns->count) return -1;
    uint64_t L[ABHED_MAX_RUNGS], R[ABHED_MAX_RUNGS];
    int k = abhed_rungs_for(ns->count, L, R, ABHED_MAX_RUNGS), ri = -1;
    for (int i = 0; i < k; i++) if (leaf >= L[i] && leaf <= R[i]) ri = i;
    if (ri < 0) return -1;
    memset(out, 0, offsetof(abhed_cond, sibs));
    memcpy(out->sid, ns->sid, ABHED_SID_LEN);
    memcpy(out->rand, ns->rands + 16 * leaf, ABHED_RAND_LEN);
    out->leaf = leaf;
    out->rung_left = L[ri];
    out->rung_right = R[ri];
    uint64_t l = leaf, r = leaf, size = 1;
    while (!(l == L[ri] && r == R[ri])) {
        if (out->nsibs >= ABHED_MAX_SIBS) return -1;
        if ((l / size) % 2 == 0) {
            memcpy(out->sibs[out->nsibs++], node(ns, r + 1, r + size), ABHED_HASH_LEN);
            r += size;
        } else {
            memcpy(out->sibs[out->nsibs++], node(ns, l - size, l - 1), ABHED_HASH_LEN);
            l -= size;
        }
        size *= 2;
    }
    return 0;
}

static const char MAGIC[8] = {'A', 'B', 'H', 'E', 'D', 'N', 'S', '1'};

int abhed_ns_save(const abhed_nodeset *ns, const char *path)
{
    char tmp[4096];
    if (snprintf(tmp, sizeof tmp, "%s.tmp", path) >= (int)sizeof tmp) return -1;
    int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) return -1;
    FILE *f = fdopen(fd, "wb");
    if (!f) { close(fd); return -1; }
    uint8_t cnt[8];
    for (int i = 0; i < 8; i++) cnt[i] = (uint8_t)(ns->count >> (56 - 8 * i));
    int ok = fwrite(MAGIC, 8, 1, f) == 1 && fwrite(ns->sid, 32, 1, f) == 1 && fwrite(cnt, 8, 1, f) == 1;
    for (uint64_t i = 0; ok && i < ns->count; i++)
        ok = fwrite(ns->levels[0] + 16 * i, 16, 1, f) == 1 && fwrite(ns->rands + 16 * i, 16, 1, f) == 1;
    ok = ok && fflush(f) == 0 && fsync(fileno(f)) == 0;
    ok = (fclose(f) == 0) && ok;
    if (!ok || rename(tmp, path) != 0) { unlink(tmp); return -1; }
    return 0;
}

abhed_nodeset *abhed_ns_load(const char *path)
{
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    char magic[8];
    uint8_t sid[32], cnt[8], h[16], r[16];
    abhed_nodeset *ns = NULL;
    if (fread(magic, 8, 1, f) != 1 || memcmp(magic, MAGIC, 8) || fread(sid, 32, 1, f) != 1 ||
        fread(cnt, 8, 1, f) != 1) goto fail;
    uint64_t n = 0;
    for (int i = 0; i < 8; i++) n = (n << 8) | cnt[i];
    ns = abhed_ns_new(sid);
    if (!ns) goto fail;
    for (uint64_t i = 0; i < n; i++) {
        if (fread(h, 16, 1, f) != 1 || fread(r, 16, 1, f) != 1) goto fail;
        if (abhed_ns_push(ns, h, r) == UINT64_MAX) goto fail;
    }
    fclose(f);
    return ns;
fail:
    abhed_ns_free(ns);
    fclose(f);
    return NULL;
}
