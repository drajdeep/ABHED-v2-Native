/*
 * Copyright 2026 Rajdeep Das, IEM-UEM, Kolkata, India
 * SPDX-License-Identifier: Apache-2.0
 * Part of ABHED-v2. See the LICENSE and NOTICE files for terms and attribution.
 */
/* Key files, BIND style: K<zone>+<alg>+<tag>.key (DNSKEY RR) and .private. */
#ifndef ABHED_KEYFILE_H
#define ABHED_KEYFILE_H
#include <ldns/ldns.h>
#include <stdint.h>

typedef struct {
    int alg;
    uint16_t flags, tag;
    ldns_rr *dnskey;          /* owned */
    ldns_key *ldnskey;        /* alg 13 only (ldns signs ECDSA) */
    uint8_t *sk;              /* alg 18 / MTL: ML-DSA-44 secret key */
    size_t sklen;
    char path[4096];          /* path prefix without extension */
} abhed_key;

int  abhed_key_load(abhed_key *k, const char *prefix);   /* 0 on success */
void abhed_key_free(abhed_key *k);
const char *abhed_alg_mnemonic(int alg);
#endif
