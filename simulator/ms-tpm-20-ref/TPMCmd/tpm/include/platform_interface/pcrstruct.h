//
// This file defines the PCR and PCR_Attributes structures and
// related interface functions
//

#ifndef _PCRSTRUCT_H_
#define _PCRSTRUCT_H_

#include <tpm_public/BaseTypes.h>
#include <tpm_public/TpmAlgorithmDefines.h>
#include <tpm_public/TpmTypes.h>

// a single PCR
typedef struct
{
#if ALG_SHA1
    BYTE Sha1Pcr[SHA1_DIGEST_SIZE];
#endif
#if ALG_SHA256
    BYTE Sha256Pcr[SHA256_DIGEST_SIZE];
#endif
#if ALG_SHA384
    BYTE Sha384[SHA384_DIGEST_SIZE];
#endif
#if ALG_SHA512
    BYTE Sha512[SHA512_DIGEST_SIZE];
#endif
#if ALG_SM3_256
    BYTE Sm3_256[SM3_256_DIGEST_SIZE];
#endif
#if ALG_SHA3_256
    BYTE Sha3_256[SHA3_256_DIGEST_SIZE];
#endif
#if ALG_SHA3_384
    BYTE Sha3_384[SHA3_384_DIGEST_SIZE];
#endif
#if ALG_SHA3_512
    BYTE Sha3_512[SHA3_512_DIGEST_SIZE];
#endif
} PCR;

// see the comments below for supportsPolicyAuth to explain this
#define MAX_PCR_GROUP_BITS 3

typedef struct
{
    // SET if the PCR value should be saved in state save
    unsigned int stateSave : 1;

    // SET if the PCR is part of the "TCB group", causes the PCR counter not to increment
    unsigned int doNotIncrementPcrCounter : 1;

    // PCRs may support policy or auth-value authorization.
    //
    // Such authorization values, if supported, are set by
    // TPM2_PCR_SetAuthPolicy and/or TPM2_PCR_SetAuthValue.
    //
    // PCRs that share the same policy/auth value are said to be in a "group".
    // PCRs that don't support authorization are said to be in group Zero.
    //
    // Group numbers are only used internally to indicate which PCRs share an
    // authorization value.  IOW the TPM client cannot refer to PCRs by group
    // number; the range of group numbers is implementation defined. zero
    // indicates the PCR doesn't support policy or auth verification.
    //
    // The size of this field must be large enough to support
    // NUM_POLICY_PCR_GROUP & NUM_AUTHVALUE_PCR_GROUP; the maximum number of groups
    // actually supported by this build of the core library.
    //
    // The number of bits allocated here does not control the number of groups,
    // but there is a static assert that the number of bits here is large
    // enough.
    unsigned int policyAuthGroup : MAX_PCR_GROUP_BITS;
    unsigned int authValuesGroup : MAX_PCR_GROUP_BITS;

    // these bitfields indicating the localities that can
    // reset or extend this PCR. A SET bit indicates the PCR can
    // be extended or reset from that locality.  The low-order bit in
    // each field is locality zero, and the high-order bit is locality 4.
    unsigned int resetLocality  : 5;
    unsigned int extendLocality : 5;
} PCR_Attributes;

// Get pointer to particular PCR from array if that PCR is allocated.
// otherwise returns NULL
BYTE* GetPcrPointerIfAllocated(PCR*       pPcrArray,
                               TPM_ALG_ID alg,       // IN: algorithm for bank
                               UINT32     pcrNumber  // IN: PCR number
);

// get a PCR pointer from the TPM's internal list, if it's allocated
// otherwise NULL
BYTE* GetPcrPointer(TPM_ALG_ID alg,       // IN: algorithm for bank
                    UINT32     pcrNumber  // IN: PCR number
);

#endif
