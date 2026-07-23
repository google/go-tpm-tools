// This file contains constant definitions used for self-test.

#ifndef _CRYPT_TEST_H
#define _CRYPT_TEST_H

// This is the definition of a bit array with one bit per algorithm.
// NOTE: Since bit numbering starts at zero, when TPM_ALG_LAST is a multiple of 8,
// ALGORITHM_VECTOR will need to have byte for the single bit in the last byte. So,
// for example, when TPM_ALG_LAST is 8, ALGORITHM_VECTOR will need 2 bytes.
#define ALGORITHM_VECTOR_BYTES ((TPM_ALG_LAST + 8) / 8)
typedef BYTE ALGORITHM_VECTOR[ALGORITHM_VECTOR_BYTES];

#ifdef TEST_SELF_TEST
LIB_EXPORT extern ALGORITHM_VECTOR LibToTest;
#endif

// This structure is used to contain self-test tracking information for the
// cryptographic modules. Each of the major modules is given a 32-bit value in
// which it may maintain its own self test information. The convention for this
// state is that when all of the bits in this structure are 0, all functions need
// to be tested.
typedef struct
{
    UINT32 rng;
    UINT32 hash;
    UINT32 sym;
#if ALG_RSA
    UINT32 rsa;
#endif
#if ALG_ECC
    UINT32 ecc;
#endif
} CRYPTO_SELF_TEST_STATE;

#endif  // _CRYPT_TEST_H
