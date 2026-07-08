
// platform PCR functions called by the TPM library

#ifndef _PLATFORM_PCR_FP_H_
#define _PLATFORM_PCR_FP_H_

#include <tpm_public/BaseTypes.h>
#include <tpm_public/TpmTypes.h>
#include <platform_interface/pcrstruct.h>

// return the number of PCRs the platform recognizes for GetPcrInitializationAttributes.
// PCRs are numbered starting at zero.
// Note: The TPM Library will enter failure mode if this number doesn't match
// IMPLEMENTATION_PCR.
UINT32 _platPcr__NumberOfPcrs(void);

// return the initialization attributes of a given PCR.
// pcrNumber expected to be in [0, _platPcr__NumberOfPcrs)
// returns the attributes for PCR[0] if the requested pcrNumber is out of range.
// Note this returns a structure by-value, which is fast because the structure is
// a bitfield.
PCR_Attributes _platPcr__GetPcrInitializationAttributes(UINT32 pcrNumber);

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
    BYTE*      pcrBuffer,        // OUT: buffer to put PCR initialization value into
    uint16_t   bufferSize,       // IN: maximum size of value buffer can hold
    uint16_t*  pcrLength);  // OUT: size of initialization value returned in pcrBuffer

// should the given PCR algorithm default to active in a new TPM?
BOOL _platPcr_IsPcrBankDefaultActive(TPM_ALG_ID pcrAlg);

#endif  // _PLATFORM_PCR_FP_H_
