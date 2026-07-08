#include "Tpm.h"
#include "Attest_spt_fp.h"
#include "GetCommandAuditDigest_fp.h"

#if CC_GetCommandAuditDigest  // Conditional expansion of this file

/*(See part 3 specification)
// Get current value of command audit log
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
TPM2_GetCommandAuditDigest(
    GetCommandAuditDigest_In*  in,  // IN: input parameter list
    GetCommandAuditDigest_Out* out  // OUT: output parameter list
)
{
    TPM_RC      result;
    TPMS_ATTEST auditInfo;
    OBJECT*     signObject = HandleToObject(in->signHandle);
    // Input validation
    if(!IsSigningObject(signObject))
        return TPM_RCS_KEY + RC_GetCommandAuditDigest_signHandle;
    if(!CryptSelectSignScheme(signObject, &in->inScheme))
        return TPM_RCS_SCHEME + RC_GetCommandAuditDigest_inScheme;

    // Command Output
    // Fill in attest information common fields
    FillInAttestInfo(in->signHandle, &in->inScheme, &in->qualifyingData, &auditInfo);

    // CommandAuditDigest specific fields
    auditInfo.type                               = TPM_ST_ATTEST_COMMAND_AUDIT;
    auditInfo.attested.commandAudit.digestAlg    = gp.auditHashAlg;
    auditInfo.attested.commandAudit.auditCounter = gp.auditCounter;

    // Copy command audit log
    auditInfo.attested.commandAudit.auditDigest = gr.commandAuditDigest;
    CommandAuditGetDigest(&auditInfo.attested.commandAudit.commandDigest);

    // Sign attestation structure.  A NULL signature will be returned if
    // signHandle is TPM_RH_NULL.  A TPM_RC_NV_UNAVAILABLE, TPM_RC_NV_RATE,
    // TPM_RC_VALUE, TPM_RC_SCHEME or TPM_RC_ATTRIBUTES error may be returned at
    // this point
    result = SignAttestInfo(signObject,
                            &in->inScheme,
                            &auditInfo,
                            &in->qualifyingData,
                            &out->auditInfo,
                            &out->signature);
    // Internal Data Update
    if(result == TPM_RC_SUCCESS && in->signHandle != TPM_RH_NULL)
        // Reset log
        gr.commandAuditDigest.t.size = 0;

    return result;
}

#endif  // CC_GetCommandAuditDigest