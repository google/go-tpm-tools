// This file contains the RSA-related structures and defines.

#ifndef _CRYPT_RSA_H
#define _CRYPT_RSA_H

// These values are used in the Crypt_Int* representation of various RSA values.
// define ci_rsa_t as buffer containing a CRYPT_INT object with space for
// (MAX_RSA_KEY_BITS) of actual data.
CRYPT_INT_TYPE(rsa, MAX_RSA_KEY_BITS);
#define CRYPT_RSA_VAR(name) CRYPT_INT_VAR(name, MAX_RSA_KEY_BITS)
#define CRYPT_RSA_INITIALIZED(name, initializer) \
    CRYPT_INT_INITIALIZED(name, MAX_RSA_KEY_BITS, initializer)

#define CRYPT_PRIME_VAR(name) CRYPT_INT_VAR(name, (MAX_RSA_KEY_BITS / 2))
// define ci_prime_t as buffer containing a CRYPT_INT object with space for
// (MAX_RSA_KEY_BITS/2) of actual data.
CRYPT_INT_TYPE(prime, (MAX_RSA_KEY_BITS / 2));
#define CRYPT_PRIME_INITIALIZED(name, initializer) \
    CRYPT_INT_INITIALIZED(name, MAX_RSA_KEY_BITS / 2, initializer)

#if !CRT_FORMAT_RSA
#  error This verson only works with CRT formatted data
#endif  // !CRT_FORMAT_RSA

typedef struct privateExponent
{
    Crypt_Int* P;
    Crypt_Int* Q;
    Crypt_Int* dP;
    Crypt_Int* dQ;
    Crypt_Int* qInv;
    ci_prime_t entries[5];
} privateExponent;

#define NEW_PRIVATE_EXPONENT(X) \
    privateExponent  _##X;      \
    privateExponent* X = RsaInitializeExponent(&(_##X))

#endif  // _CRYPT_RSA_H
