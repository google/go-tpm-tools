#include "Tpm.h"
#include "Attest_spt_fp.h"
#include "GetSessionAuditDigest_fp.h"

#if CC_GetSessionAuditDigest  // Conditional expansion of this file

/*(See part 3 specification)
// Get audit session digest
*/
//  Return Type: TPM_RC
//      TPM_RC_KEY          key referenced by 'signHandle' is not a signing key
//      TPM_RC_SCHEME       'inScheme' is incompatible with 'signHandle' type; or
//                          both 'scheme' and key's default scheme are empty; or
//                          'scheme' is empty while key's default scheme requires
//                          explicit input scheme (split signing); or
//                          non-empty default key scheme differs from 'scheme'
//      TPM_RC_TYPE         'sessionHandle' does not reference an audit session
//      TPM_RC_VALUE        digest generated for the given 'scheme' is greater than
//                          the modulus of 'signHandle' (for an RSA key);
//                          invalid commit status or failed to generate "r" value
//                          (for an ECC key)
TPM_RC
TPM2_GetSessionAuditDigest(
    GetSessionAuditDigest_In*  in,  // IN: input parameter list
    GetSessionAuditDigest_Out* out  // OUT: output parameter list
)
{
    SESSION* session = SessionGet(in->sessionHandle);
    pAssert_RC(session);
    TPMS_ATTEST auditInfo;
    OBJECT*     signObject = HandleToObject(in->signHandle);
    // Input Validation
    if(!IsSigningObject(signObject))
        return TPM_RCS_KEY + RC_GetSessionAuditDigest_signHandle;
    if(!CryptSelectSignScheme(signObject, &in->inScheme))
        return TPM_RCS_SCHEME + RC_GetSessionAuditDigest_inScheme;

    // session must be an audit session
    if(session->attributes.isAudit == CLEAR)
        return TPM_RCS_TYPE + RC_GetSessionAuditDigest_sessionHandle;

    // Command Output
    // Fill in attest information common fields
    FillInAttestInfo(in->signHandle, &in->inScheme, &in->qualifyingData, &auditInfo);

    // SessionAuditDigest specific fields
    auditInfo.type                                = TPM_ST_ATTEST_SESSION_AUDIT;
    auditInfo.attested.sessionAudit.sessionDigest = session->u2.auditDigest;

    // Exclusive audit session
    auditInfo.attested.sessionAudit.exclusiveSession =
        (g_exclusiveAuditSession == in->sessionHandle);

    // Sign attestation structure.  A NULL signature will be returned if
    // signObject is NULL.
    return SignAttestInfo(signObject,
                          &in->inScheme,
                          &auditInfo,
                          &in->qualifyingData,
                          &out->auditInfo,
                          &out->signature);
}

#endif  // CC_GetSessionAuditDigest