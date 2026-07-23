#include "Tpm.h"
#include "Attest_spt_fp.h"
#include "Quote_fp.h"

#if CC_Quote  // Conditional expansion of this file

/*(See part 3 specification)
// quote PCR values
*/
//  Return Type: TPM_RC
//      TPM_RC_KEY              'signHandle' does not reference a signing key;
//      TPM_RC_SCHEME           the scheme is not compatible with sign key type,
//                              or input scheme is not compatible with default
//                              scheme, or the chosen scheme is not a valid
//                              sign scheme
TPM_RC
TPM2_Quote(Quote_In*  in,  // IN: input parameter list
           Quote_Out* out  // OUT: output parameter list
)
{
    TPMI_ALG_HASH hashAlg;
    TPMS_ATTEST   quoted;
    OBJECT*       signObject = HandleToObject(in->signHandle);
    // Input Validation
    if(!IsSigningObject(signObject))
        return TPM_RCS_KEY + RC_Quote_signHandle;
    if(!CryptSelectSignScheme(signObject, &in->inScheme))
        return TPM_RCS_SCHEME + RC_Quote_inScheme;

    // Command Output

    // Filling in attest information
    // Common fields
    // FillInAttestInfo may return TPM_RC_SCHEME or TPM_RC_KEY
    FillInAttestInfo(in->signHandle, &in->inScheme, &in->qualifyingData, &quoted);

    // Quote specific fields
    // Attestation type
    quoted.type = TPM_ST_ATTEST_QUOTE;

    // Get hash algorithm in sign scheme.  This hash algorithm is used to
    // compute PCR digest. If there is no algorithm, then the PCR cannot
    // be digested and this command returns TPM_RC_SCHEME
    hashAlg = in->inScheme.details.any.hashAlg;

    if(hashAlg == TPM_ALG_NULL)
        return TPM_RCS_SCHEME + RC_Quote_inScheme;

    // Compute PCR digest
    TPM_RC result = PCRComputeCurrentDigest(
        hashAlg, &in->PCRselect, &quoted.attested.quote.pcrDigest);

    if(result != TPM_RC_SUCCESS)
        return result;

    // Copy PCR select.  "PCRselect" is modified in PCRComputeCurrentDigest
    // function
    quoted.attested.quote.pcrSelect = in->PCRselect;

    // Sign attestation structure.  A NULL signature will be returned if
    // signObject is NULL.

    result = SignAttestInfo(signObject,
                            &in->inScheme,
                            &quoted,
                            &in->qualifyingData,
                            &out->quoted,
                            &out->signature);

    return result;
}

#endif  // CC_Quote