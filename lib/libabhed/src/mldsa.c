/*
 * Copyright 2026 Rajdeep Das, IEM-UEM, Kolkata, India
 * SPDX-License-Identifier: Apache-2.0
 * Part of ABHED-v2. See the LICENSE and NOTICE files for terms and attribution.
 */
/* ML-DSA-44 through liboqs: pure ML-DSA, empty context string (draft-westerbaan-dnssec-mldsa). */
#include <string.h>
#include <oqs/oqs.h>
#include "abhed/abhed.h"

int abhed_mldsa44_keygen(uint8_t pk[ABHED_MLDSA44_PK_LEN], uint8_t sk[ABHED_MLDSA44_SK_LEN])
{
    return OQS_SIG_ml_dsa_44_keypair(pk, sk) == OQS_SUCCESS ? 0 : -1;
}

int abhed_mldsa44_sign(uint8_t sig[ABHED_MLDSA44_SIG_LEN], size_t *siglen,
                       const uint8_t *msg, size_t msglen, const uint8_t *sk)
{
    return OQS_SIG_ml_dsa_44_sign(sig, siglen, msg, msglen, sk) == OQS_SUCCESS ? 0 : -1;
}

int abhed_mldsa44_verify(const uint8_t *pk, size_t pklen, const uint8_t *msg, size_t msglen,
                         const uint8_t *sig, size_t siglen)
{
    if (pklen != ABHED_MLDSA44_PK_LEN || siglen != ABHED_MLDSA44_SIG_LEN) return 0;
    return OQS_SIG_ml_dsa_44_verify(msg, msglen, sig, siglen, pk) == OQS_SUCCESS;
}
