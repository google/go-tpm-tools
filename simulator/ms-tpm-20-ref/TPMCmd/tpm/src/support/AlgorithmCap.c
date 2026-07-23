//** Description
// This file contains the algorithm property definitions for the algorithms and the
// code for the TPM2_GetCapability() to return the algorithm properties.

//** Includes and Defines

#include "Tpm.h"

typedef struct
{
    TPM_ALG_ID     algID;
    TPMA_ALGORITHM attributes;
} ALGORITHM;

static const ALGORITHM s_algorithms[] = {
// The entries in this table need to be in ascending order but the table doesn't
// need to be full (gaps are allowed). One day, a tool might exist to fill in the
// table from the TPM_ALG description
#if ALG_RSA
    {TPM_ALG_RSA, TPMA_ALGORITHM_INITIALIZER(1, 0, 0, 1, 0, 0, 0, 0, 0)},
#endif
#if ALG_SHA1
    {TPM_ALG_SHA1, TPMA_ALGORITHM_INITIALIZER(0, 0, 1, 0, 0, 0, 0, 0, 0)},
#endif

    {TPM_ALG_HMAC, TPMA_ALGORITHM_INITIALIZER(0, 0, 1, 0, 0, 1, 0, 0, 0)},

#if ALG_AES
    {TPM_ALG_AES, TPMA_ALGORITHM_INITIALIZER(0, 1, 0, 0, 0, 0, 0, 0, 0)},
#endif
#if ALG_MGF1
    {TPM_ALG_MGF1, TPMA_ALGORITHM_INITIALIZER(0, 0, 1, 0, 0, 0, 0, 1, 0)},
#endif

    {TPM_ALG_KEYEDHASH, TPMA_ALGORITHM_INITIALIZER(0, 0, 1, 1, 0, 1, 1, 0, 0)},

#if ALG_XOR
    {TPM_ALG_XOR, TPMA_ALGORITHM_INITIALIZER(0, 1, 1, 0, 0, 0, 0, 0, 0)},
#endif

#if ALG_SHA256
    {TPM_ALG_SHA256, TPMA_ALGORITHM_INITIALIZER(0, 0, 1, 0, 0, 0, 0, 0, 0)},
#endif
#if ALG_SHA384
    {TPM_ALG_SHA384, TPMA_ALGORITHM_INITIALIZER(0, 0, 1, 0, 0, 0, 0, 0, 0)},
#endif
#if ALG_SHA512
    {TPM_ALG_SHA512, TPMA_ALGORITHM_INITIALIZER(0, 0, 1, 0, 0, 0, 0, 0, 0)},
#endif
#if ALG_SM3_256
    {TPM_ALG_SM3_256, TPMA_ALGORITHM_INITIALIZER(0, 0, 1, 0, 0, 0, 0, 0, 0)},
#endif
#if ALG_SM4
    {TPM_ALG_SM4, TPMA_ALGORITHM_INITIALIZER(0, 1, 0, 0, 0, 0, 0, 0, 0)},
#endif
#if ALG_RSASSA
    {TPM_ALG_RSASSA, TPMA_ALGORITHM_INITIALIZER(1, 0, 0, 0, 0, 1, 0, 0, 0)},
#endif
#if ALG_RSAES
    {TPM_ALG_RSAES, TPMA_ALGORITHM_INITIALIZER(1, 0, 0, 0, 0, 0, 1, 0, 0)},
#endif
#if ALG_RSAPSS
    {TPM_ALG_RSAPSS, TPMA_ALGORITHM_INITIALIZER(1, 0, 0, 0, 0, 1, 0, 0, 0)},
#endif
#if ALG_OAEP
    {TPM_ALG_OAEP, TPMA_ALGORITHM_INITIALIZER(1, 0, 0, 0, 0, 0, 1, 0, 0)},
#endif
#if ALG_ECDSA
    {TPM_ALG_ECDSA, TPMA_ALGORITHM_INITIALIZER(1, 0, 0, 0, 0, 1, 0, 0, 0)},
#endif
#if ALG_ECDH
    {TPM_ALG_ECDH, TPMA_ALGORITHM_INITIALIZER(1, 0, 0, 0, 0, 0, 0, 1, 0)},
#endif
#if ALG_ECDAA
    {TPM_ALG_ECDAA, TPMA_ALGORITHM_INITIALIZER(1, 0, 0, 0, 0, 1, 0, 0, 0)},
#endif
#if ALG_SM2
    {TPM_ALG_SM2, TPMA_ALGORITHM_INITIALIZER(1, 0, 0, 0, 0, 1, 0, 1, 0)},
#endif
#if ALG_ECSCHNORR
    {TPM_ALG_ECSCHNORR, TPMA_ALGORITHM_INITIALIZER(1, 0, 0, 0, 0, 1, 0, 0, 0)},
#endif
#if ALG_ECMQV
    {TPM_ALG_ECMQV, TPMA_ALGORITHM_INITIALIZER(1, 0, 0, 0, 0, 0, 0, 1, 0)},
#endif
#if ALG_KDF1_SP800_56A
    {TPM_ALG_KDF1_SP800_56A, TPMA_ALGORITHM_INITIALIZER(0, 0, 1, 0, 0, 0, 0, 1, 0)},
#endif
#if ALG_KDF2
    {TPM_ALG_KDF2, TPMA_ALGORITHM_INITIALIZER(0, 0, 1, 0, 0, 0, 0, 1, 0)},
#endif
#if ALG_KDF1_SP800_108
    {TPM_ALG_KDF1_SP800_108, TPMA_ALGORITHM_INITIALIZER(0, 0, 1, 0, 0, 0, 0, 1, 0)},
#endif
#if ALG_ECC
    {TPM_ALG_ECC, TPMA_ALGORITHM_INITIALIZER(1, 0, 0, 1, 0, 0, 0, 0, 0)},
#endif

    {TPM_ALG_SYMCIPHER, TPMA_ALGORITHM_INITIALIZER(0, 0, 0, 1, 0, 0, 0, 0, 0)},

#if ALG_CAMELLIA
    {TPM_ALG_CAMELLIA, TPMA_ALGORITHM_INITIALIZER(0, 1, 0, 0, 0, 0, 0, 0, 0)},
#endif
#if ALG_CMAC
    {TPM_ALG_CMAC, TPMA_ALGORITHM_INITIALIZER(0, 1, 0, 0, 0, 1, 0, 0, 0)},
#endif
#if ALG_CTR
    {TPM_ALG_CTR, TPMA_ALGORITHM_INITIALIZER(0, 1, 0, 0, 0, 0, 1, 0, 0)},
#endif
#if ALG_OFB
    {TPM_ALG_OFB, TPMA_ALGORITHM_INITIALIZER(0, 1, 0, 0, 0, 0, 1, 0, 0)},
#endif
#if ALG_CBC
    {TPM_ALG_CBC, TPMA_ALGORITHM_INITIALIZER(0, 1, 0, 0, 0, 0, 1, 0, 0)},
#endif
#if ALG_CFB
    {TPM_ALG_CFB, TPMA_ALGORITHM_INITIALIZER(0, 1, 0, 0, 0, 0, 1, 0, 0)},
#endif
#if ALG_ECB
    {TPM_ALG_ECB, TPMA_ALGORITHM_INITIALIZER(0, 1, 0, 0, 0, 0, 1, 0, 0)},
#endif
};

//** AlgorithmCapGetImplemented()
// This function is used by TPM2_GetCapability() to return a list of the
// implemented algorithms.
//
//  Return Type: TPMI_YES_NO
//  YES        more algorithms to report
//  NO         no more algorithms to report
TPMI_YES_NO
AlgorithmCapGetImplemented(TPM_ALG_ID algID,  // IN: the starting algorithm ID
                           UINT32     count,  // IN: count of returned algorithms
                           TPML_ALG_PROPERTY* algList  // OUT: algorithm list
)
{
    TPMI_YES_NO more = NO;
    UINT32      i;
    UINT32      algNum;

    // initialize output algorithm list
    algList->count = 0;

    // The maximum count of algorithms we may return is MAX_CAP_ALGS.
    if(count > MAX_CAP_ALGS)
        count = MAX_CAP_ALGS;

    // Compute how many algorithms are defined in s_algorithms array.
    algNum = sizeof(s_algorithms) / sizeof(s_algorithms[0]);

    // Scan the implemented algorithm list to see if there is a match to 'algID'.
    for(i = 0; i < algNum; i++)
    {
        // If algID is less than the starting algorithm ID, skip it
        if(s_algorithms[i].algID < algID)
            continue;
        if(algList->count < count)
        {
            // If we have not filled up the return list, add more algorithms
            // to it
            algList->algProperties[algList->count].alg = s_algorithms[i].algID;
            algList->algProperties[algList->count].algProperties =
                s_algorithms[i].attributes;
            algList->count++;
        }
        else
        {
            // If the return list is full but we still have algorithms
            // available, report this and stop scanning.
            more = YES;
            break;
        }
    }

    return more;
}

//** AlgorithmCapGetOneImplemented()
// This function returns whether a single algorithm was implemented, along
// with its properties (if implemented).
BOOL AlgorithmCapGetOneImplemented(
    TPM_ALG_ID         algID,       // IN: the algorithm ID
    TPMS_ALG_PROPERTY* algProperty  // OUT: algorithm properties
)
{
    UINT32 i;
    UINT32 algNum;

    // Compute how many algorithms are defined in s_algorithms array.
    algNum = sizeof(s_algorithms) / sizeof(s_algorithms[0]);

    // Scan the implemented algorithm list to see if there is a match to 'algID'.
    for(i = 0; i < algNum; i++)
    {
        // If algID is less than the starting algorithm ID, skip it
        if(s_algorithms[i].algID == algID)
        {
            algProperty->alg           = algID;
            algProperty->algProperties = s_algorithms[i].attributes;
            return TRUE;
        }
    }

    return FALSE;
}

//** AlgorithmGetImplementedVector()
// This function returns the bit vector of the implemented algorithms.
LIB_EXPORT
void AlgorithmGetImplementedVector(
    ALGORITHM_VECTOR* implemented  // OUT: the implemented bits are SET
)
{
    int index;

    // Nothing implemented until we say it is
    MemorySet(implemented, 0, sizeof(ALGORITHM_VECTOR));
    // Go through the list of implemented algorithms and SET the corresponding bit in
    // in the implemented vector
    for(index = (sizeof(s_algorithms) / sizeof(s_algorithms[0])) - 1; index >= 0;
        index--)
        SET_BIT(s_algorithms[index].algID, *implemented);
    return;
}