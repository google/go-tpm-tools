
// PCR platform interface functions
#include "Platform.h"
#include <tpm_public/TpmAlgorithmDefines.h>

// use this as a convenient lookup for hash size for PCRs.
UINT16 CryptHashGetDigestSize(TPM_ALG_ID hashAlg  // IN: hash algorithm to look up
);
void   MemorySet(void* dest, int value, size_t size);

// The initial value of PCR attributes.  The value of these fields should be
// consistent with PC Client specification.  The bitfield meanings are defined by
// the TPM Reference code.
// In this implementation, we assume the total number of implemented PCR is 24.
static const PCR_Attributes s_initAttributes[] = {
    //
    // PCR 0 - 15, static RTM
    // PCR[0]
    {
        1,  // save state
        0,  // in the "do not increment the PcrCounter" group? (0 = increment the PcrCounter)
        0,  // supportsPolicyAuth group number? 0 = policyAuth not supported for this PCR.
        0,  // supportsAuthValue group number? 0 = AuthValue not supported for this PCR.
        0,    // 0 = reset localities (cannot reset)
        0x1F  // 0x1F = extendlocalities [0,4]
    },
    {1, 0, 0, 0, 0, 0x1F},  // PCR 1-3
    {1, 0, 0, 0, 0, 0x1F},
    {1, 0, 0, 0, 0, 0x1F},
    {1, 0, 0, 0, 0, 0x1F},  // PCR 4-6
    {1, 0, 0, 0, 0, 0x1F},
    {1, 0, 0, 0, 0, 0x1F},
    {1, 0, 0, 0, 0, 0x1F},  // PCR 7-9
    {1, 0, 0, 0, 0, 0x1F},
    {1, 0, 0, 0, 0, 0x1F},
    {1, 0, 0, 0, 0, 0x1F},  // PCR 10-12
    {1, 0, 0, 0, 0, 0x1F},
    {1, 0, 0, 0, 0, 0x1F},
    {1, 0, 0, 0, 0, 0x1F},  // PCR 13-15
    {1, 0, 0, 0, 0, 0x1F},
    {1, 0, 0, 0, 0, 0x1F},

    // these PCRs are never saved
    {0, 0, 0, 0, 0x0F, 0x1F},  // PCR 16, Debug, reset allowed, extend all
    {0, 0, 0, 0, 0x10, 0x1C},  // PCR 17, Locality 4, extend loc 2+
    {0, 0, 0, 0, 0x10, 0x1C},  // PCR 18, Locality 3, extend loc 2+
    {0, 0, 0, 0, 0x10, 0x0C},  // PCR 19, Locality 2, extend loc 2, 3
    // these three support doNotIncrement, PolicyAuth, and AuthValue.
    // this is consistent with the existing behavior of the TPM Reference code
    // but differs from the behavior of the PC client spec.
    {0, 1, 1, 1, 0x14, 0x0E},  // PCR 20, Locality 1, extend loc 1, 2, 3
    {0, 1, 1, 1, 0x14, 0x04},  // PCR 21, Dynamic OS, extend loc 2
    {0, 1, 1, 1, 0x14, 0x04},  // PCR 22, Dynamic OS, extend loc 2
    {0, 0, 0, 0, 0x0F, 0x1F},  // PCR 23, reset allowed, App specific, extend all
};

#ifndef ARRAYSIZE
#  define ARRAYSIZE(a) (sizeof(a) / sizeof(a[0]))
#endif

MUST_BE(ARRAYSIZE(s_initAttributes) == IMPLEMENTATION_PCR);

#if ALG_SHA256 != YES && ALG_SHA384 != YES
#  error No default PCR banks defined
#endif

static const TPM_ALG_ID DefaultActivePcrBanks[] = {
#if ALG_SHA1
    TPM_ALG_SHA1,
#endif
#if ALG_SHA256
    TPM_ALG_SHA256,
#endif
#if ALG_SHA384
    TPM_ALG_SHA384,
#endif
};

UINT32 _platPcr__NumberOfPcrs()
{
    return ARRAYSIZE(s_initAttributes);
}

// return the initialization attributes of a given PCR.
// pcrNumber expected to be in [0, _platPcr__NumberOfPcrs)
// returns the attributes for PCR[0] if the requested pcrNumber is out of range.
PCR_Attributes _platPcr__GetPcrInitializationAttributes(UINT32 pcrNumber)
{
    if(pcrNumber >= _platPcr__NumberOfPcrs())
    {
        pcrNumber = 0;
    }
    return s_initAttributes[pcrNumber];
}

// should the given PCR algorithm default to active in a new TPM?
BOOL _platPcr_IsPcrBankDefaultActive(TPM_ALG_ID pcrAlg)
{
    // brute force search is fast enough for a small array.
    for(size_t i = 0; i < ARRAYSIZE(DefaultActivePcrBanks); i++)
    {
        if(DefaultActivePcrBanks[i] == pcrAlg)
        {
            return TRUE;
        }
    }
    return FALSE;
}

// Fill a given buffer with the PCR initialization value for a particular PCR and hash
// combination, and return its length.  If the platform doesn't have a value, then
// the result size is expected to be zero, and the rfunction will return TPM_RC_PCR.
// If a valid is not available, then the core TPM library will ignore the value and
// treat it as non-existant and provide a default.
// If the buffer is not large enough for a pcr consistent with pcrAlg, then the
// platform will return TPM_RC_FAILURE.
TPM_RC _platPcr__GetInitialValueForPcr(
    UINT32     pcrNumber,        // IN: PCR to be initialized
    TPM_ALG_ID pcrAlg,           // IN: Algorithm of the PCR Bank being initialized
    BYTE       startupLocality,  // IN: locality where startup is being called from
    BYTE*      pcrData,          // OUT: buffer to put PCR initialization value into
    uint16_t   bufferSize,       // IN: maximum size of value buffer can hold
    uint16_t*  pcrLength  // OUT: size of initialization value returned in pcrBuffer
)
{
    // If the reset locality contains locality 4, then this
    // indicates a DRTM PCR where the reset value is all ones,
    // otherwise it is all zero.  Don't check with equal because
    // resetLocality is a bitfield of multiple values and does
    // not support extended localities.
    uint16_t pcrSize = CryptHashGetDigestSize(pcrAlg);
    pAssert_RC(pcrNumber < _platPcr__NumberOfPcrs());
    pAssert_RC(bufferSize >= pcrSize) pAssert_RC(pcrLength != NULL);

    PCR_Attributes pcrAttributes =
        _platPcr__GetPcrInitializationAttributes(pcrNumber);
    BYTE defaultValue = 0;
    // PCRs that can be cleared from locality 4 are DRTM and initialize to all 0xFF
    if((pcrAttributes.resetLocality & 0x10) != 0)
    {
        defaultValue = 0xFF;
    }
    MemorySet(pcrData, defaultValue, pcrSize);
    if(pcrNumber == HCRTM_PCR)
    {
        pcrData[pcrSize - 1] = startupLocality;
    }

    // platform could provide a value here if the platform has initialization rules
    // different from the original PC Client spec (the default used by the Core library).
    *pcrLength = pcrSize;
    return TPM_RC_SUCCESS;
}
