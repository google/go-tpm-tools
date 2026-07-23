//** Introduction
//
// This file contains prototypes that are common to all TPM crypto interfaces.
//
#ifndef CRYPTO_INTERFACE_H
#define CRYPTO_INTERFACE_H

#include "TpmConfiguration/TpmBuildSwitches.h"

#if SIMULATION && CRYPTO_LIB_REPORTING

typedef struct crypto_impl_description
{
    // The name of the crypto library, ASCII encoded.
    char name[32];
    // The version of the crypto library, ASCII encoded.
    char version[32];
} _CRYPTO_IMPL_DESCRIPTION;

// When building the simulator, the plugged-in crypto libraries can report its
// version information by implementing these interfaces.
void _crypto_GetSymImpl(_CRYPTO_IMPL_DESCRIPTION* result);
void _crypto_GetHashImpl(_CRYPTO_IMPL_DESCRIPTION* result);
void _crypto_GetMathImpl(_CRYPTO_IMPL_DESCRIPTION* result);

#endif  // SIMULATION && CRYPTO_LIB_REPORTING

#endif  // CRYPTO_INTERFACE_H
