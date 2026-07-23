#include "Tpm.h"
#include "Sign_fp.h"

#if CC_Sign  // Conditional expansion of this file

#  include "Attest_spt_fp.h"

/*(See part 3 specification)
// sign an externally provided hash using an asymmetric signing key
*/
//  Return Type: TPM_RC
//      TPM_RC_BINDING          The public and private portions of the key are not
//                              properly bound.
//      TPM_RC_KEY              'signHandle' does not reference a signing key;
//      TPM_RC_SCHEME           the scheme is not compatible with sign key type,
//                              or input scheme is not compatible with default
//                              scheme, or the chosen scheme is not a valid
//                              sign scheme, or the scheme hashAlg is not a
//                              valid hash algorithm
//      TPM_RC_TICKET           'validation' is not a valid ticket
//      TPM_RC_VALUE            the value to sign is larger than allowed for the
//                              type of 'keyHandle'
//      TPM_RC_ATTRIBUTES       the key has the x509sign attribute and can't be
//                              used in TPM2_Sign()
//      TPM_RC_SIZE             the provided 'digest' does not match the size
//                              of the scheme hashAlg digest

TPM_RC
TPM2_Sign(Sign_In*  in,  // IN: input parameter list
          Sign_Out* out  // OUT: output parameter list
)
{
    TPM_RC            result;
    TPMT_TK_HASHCHECK ticket;
    OBJECT*           signObject = HandleToObject(in->keyHandle);
    //
    // Input Validation
    if(!IsSigningObject(signObject))
    {
        return TPM_RCS_KEY + RC_Sign_keyHandle;
    }

    // A key that will be used for x.509 signatures can't be used in TPM2_Sign().
    if(IS_ATTRIBUTE(signObject->publicArea.objectAttributes, TPMA_OBJECT, x509sign))
    {
        return TPM_RCS_ATTRIBUTES + RC_Sign_keyHandle;
    }

    // Pick a scheme for signing. If the input signing scheme is not compatible
    // with the default scheme or the signing key type, return an error. If a
    // valid hash algorithm is not specified, return an error.
    if(!CryptSelectSignScheme(signObject, &in->inScheme))
    {
        return TPM_RCS_SCHEME + RC_Sign_inScheme;
    }

    // If validation is provided, or the key is restricted, check the ticket
    if(in->validation.digest.t.size != 0
       || IS_ATTRIBUTE(
           signObject->publicArea.objectAttributes, TPMA_OBJECT, restricted))
    {
        // Compute and compare ticket
        result = TicketComputeHashCheck(in->validation.hierarchy,
                                        in->inScheme.details.any.hashAlg,
                                        &in->digest,
                                        &ticket);
        if(result != TPM_RC_SUCCESS)
            return result;

        if(!MemoryEqual2B(&in->validation.digest.b, &ticket.digest.b))
            return TPM_RCS_TICKET + RC_Sign_validation;
    }
    else
    // If we don't have a ticket, at least verify that the provided 'digest'
    // is the size of the scheme hashAlg digest.
    // NOTE: this does not guarantee that the 'digest' is actually produced using
    // the indicated hash algorithm, but at least it might be.
    {
        if(in->digest.t.size
           != CryptHashGetDigestSize(in->inScheme.details.any.hashAlg))
            return TPM_RCS_SIZE + RC_Sign_digest;
    }

    // Command Output
    // Sign the hash. A TPM_RC_VALUE or TPM_RC_SCHEME
    // error may be returned at this point
    result = CryptSign(signObject, &in->inScheme, &in->digest, &out->signature);

    return result;
}

#endif  // CC_Sign