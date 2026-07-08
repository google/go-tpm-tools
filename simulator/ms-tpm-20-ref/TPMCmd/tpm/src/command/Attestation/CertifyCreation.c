#include "Tpm.h"
#include "Attest_spt_fp.h"
#include "CertifyCreation_fp.h"

#if CC_CertifyCreation  // Conditional expansion of this file

/*(See part 3 specification)
// Prove the association between an object and its creation data
*/
//  Return Type: TPM_RC
//      TPM_RC_KEY          key referenced by 'signHandle' is not a signing key
//      TPM_RC_SCHEME       'inScheme' is not compatible with 'signHandle'
//      TPM_RC_TICKET       'creationTicket' does not match 'objectHandle'
//      TPM_RC_VALUE        digest generated for 'inScheme' is greater or has larger
//                          size than the modulus of 'signHandle', or the buffer for
//                          the result in 'signature' is too small (for an RSA key);
//                          invalid commit status (for an ECC key with a split scheme).
TPM_RC
TPM2_CertifyCreation(CertifyCreation_In*  in,  // IN: input parameter list
                     CertifyCreation_Out* out  // OUT: output parameter list
)
{
    TPM_RC           result = TPM_RC_SUCCESS;
    TPMT_TK_CREATION ticket;
    TPMS_ATTEST      certifyInfo;
    OBJECT*          certified  = HandleToObject(in->objectHandle);
    OBJECT*          signObject = HandleToObject(in->signHandle);
    // Input Validation
    if(!IsSigningObject(signObject))
        return TPM_RCS_KEY + RC_CertifyCreation_signHandle;
    if(!CryptSelectSignScheme(signObject, &in->inScheme))
        return TPM_RCS_SCHEME + RC_CertifyCreation_inScheme;

    pAssert_RC(certified != NULL);
    // CertifyCreation specific input validation
    // Re-compute ticket
    result = TicketComputeCreation(
        in->creationTicket.hierarchy, &certified->name, &in->creationHash, &ticket);
    if(result != TPM_RC_SUCCESS)
        return result;

    // Compare ticket
    if(!MemoryEqual2B(&ticket.digest.b, &in->creationTicket.digest.b))
        return TPM_RCS_TICKET + RC_CertifyCreation_creationTicket;

    // Command Output
    // Common fields
    FillInAttestInfo(
        in->signHandle, &in->inScheme, &in->qualifyingData, &certifyInfo);

    // CertifyCreation specific fields
    // Attestation type
    certifyInfo.type                         = TPM_ST_ATTEST_CREATION;
    certifyInfo.attested.creation.objectName = certified->name;

    // Copy the creationHash
    certifyInfo.attested.creation.creationHash = in->creationHash;

    // Sign attestation structure.  A NULL signature will be returned if
    // signObject is TPM_RH_NULL.  A TPM_RC_NV_UNAVAILABLE, TPM_RC_NV_RATE,
    // TPM_RC_VALUE, TPM_RC_SCHEME or TPM_RC_ATTRIBUTES error may be returned at
    // this point
    return SignAttestInfo(signObject,
                          &in->inScheme,
                          &certifyInfo,
                          &in->qualifyingData,
                          &out->certifyInfo,
                          &out->signature);
}

#endif  // CC_CertifyCreation