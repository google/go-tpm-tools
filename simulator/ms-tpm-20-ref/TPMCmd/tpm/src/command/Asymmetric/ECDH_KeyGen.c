#include "Tpm.h"
#include "ECDH_KeyGen_fp.h"

#if CC_ECDH_KeyGen  // Conditional expansion of this file

/*(See part 3 specification)
// This command uses the TPM to generate an ephemeral public key and the product
// of the ephemeral private key and the public portion of an ECC key.
*/
//  Return Type: TPM_RC
//      TPM_RC_KEY              'keyHandle' does not reference an ECC key
TPM_RC
TPM2_ECDH_KeyGen(ECDH_KeyGen_In*  in,  // IN: input parameter list
                 ECDH_KeyGen_Out* out  // OUT: output parameter list
)
{
    OBJECT*             eccKey;
    TPM2B_ECC_PARAMETER sensitive;
    TPM_RC              result;

    // Input Validation

    eccKey = HandleToObject(in->keyHandle);
    pAssert_RC(eccKey != NULL);

    // Referenced key must be an ECC key
    if(eccKey->publicArea.type != TPM_ALG_ECC)
        return TPM_RCS_KEY + RC_ECDH_KeyGen_keyHandle;

    // Command Output
    do
    {
        TPMT_PUBLIC* keyPublic = &eccKey->publicArea;
        // Create ephemeral ECC key
        result = CryptEccNewKeyPair(&out->pubPoint.point,
                                    &sensitive,
                                    keyPublic->parameters.eccDetail.curveID);
        if(result == TPM_RC_SUCCESS)
        {
            // Compute Z
            result = CryptEccPointMultiply(&out->zPoint.point,
                                           keyPublic->parameters.eccDetail.curveID,
                                           &keyPublic->unique.ecc,
                                           &sensitive,
                                           NULL,
                                           NULL);
            // The point in the key is not on the curve. Indicate
            // that the key is bad.
            if(result == TPM_RC_ECC_POINT)
                return TPM_RCS_KEY + RC_ECDH_KeyGen_keyHandle;
            // The other possible error from CryptEccPointMultiply is
            // TPM_RC_NO_RESULT indicating that the multiplication resulted in
            // the point at infinity, so get a new random key and start over
            // BTW, this never happens.
        }
    } while(result == TPM_RC_NO_RESULT);
    return result;
}

#endif  // CC_ECDH_KeyGen