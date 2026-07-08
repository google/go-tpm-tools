#include "Tpm.h"
#include "Attest_spt_fp.h"
#include "GetTime_fp.h"

#if CC_GetTime  // Conditional expansion of this file

/*(See part 3 specification)
// Applies a time stamp to the passed blob (qualifyingData).
*/
//  Return Type: TPM_RC
//      TPM_RC_KEY          key referenced by 'signHandle' is not a signing key
//      TPM_RC_SCHEME       'inScheme' is incompatible with 'signHandle' type; or
//                          both 'scheme' and key's default scheme are empty; or
//                          'scheme' is empty while key's default scheme requires
//                          explicit input scheme (split signing); or
//                          non-empty default key scheme differs from 'scheme'
//      TPM_RC_VALUE        digest generated for the given 'scheme' is greater than
//                          the modulus of 'signHandle' (for an RSA key);
//                          invalid commit status or failed to generate "r" value
//                          (for an ECC key)
TPM_RC
TPM2_GetTime(GetTime_In*  in,  // IN: input parameter list
             GetTime_Out* out  // OUT: output parameter list
)
{
    TPMS_ATTEST timeInfo;
    OBJECT*     signObject = HandleToObject(in->signHandle);
    // Input Validation
    if(!IsSigningObject(signObject))
        return TPM_RCS_KEY + RC_GetTime_signHandle;
    if(!CryptSelectSignScheme(signObject, &in->inScheme))
        return TPM_RCS_SCHEME + RC_GetTime_inScheme;

    // Command Output
    // Fill in attest common fields
    FillInAttestInfo(in->signHandle, &in->inScheme, &in->qualifyingData, &timeInfo);

    // GetClock specific fields
    timeInfo.type                    = TPM_ST_ATTEST_TIME;
    timeInfo.attested.time.time.time = g_time;
    TimeFillInfo(&timeInfo.attested.time.time.clockInfo);

    // Firmware version in plain text
    timeInfo.attested.time.firmwareVersion =
        (((UINT64)gp.firmwareV1) << 32) + gp.firmwareV2;

    // Sign attestation structure.  A NULL signature will be returned if
    // signObject is NULL.
    TPM_RC rc = SignAttestInfo(signObject,
                               &in->inScheme,
                               &timeInfo,
                               &in->qualifyingData,
                               &out->timeInfo,
                               &out->signature);

    return rc;
}

#endif  // CC_GetTime