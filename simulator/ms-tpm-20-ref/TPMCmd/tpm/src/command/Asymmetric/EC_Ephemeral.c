#include "Tpm.h"
#include "EC_Ephemeral_fp.h"

#if CC_EC_Ephemeral  // Conditional expansion of this file

/*(See part 3 specification)
// This command creates an ephemeral key using the commit mechanism
*/
//  Return Type: TPM_RC
// TPM_RC_NO_RESULT             the TPM is not able to generate an 'r' value
TPM_RC
TPM2_EC_Ephemeral(EC_Ephemeral_In*  in,  // IN: input parameter list
                  EC_Ephemeral_Out* out  // OUT: output parameter list
)
{
    TPM2B_ECC_PARAMETER r;
    TPM_RC              result;
    //
    do
    {
        // Get the random value that will be used in the point multiplications
        // Note: this does not commit the count.
        if(!CryptGenerateR(&r, NULL, in->curveID, NULL))
            return TPM_RC_NO_RESULT;
        // do a point multiply
        result =
            CryptEccPointMultiply(&out->Q.point, in->curveID, NULL, &r, NULL, NULL);
        // commit the count value if either the r value results in the point at
        // infinity or if the value is good. The commit on the r value for infinity
        // is so that the r value will be skipped.
        if((result == TPM_RC_SUCCESS) || (result == TPM_RC_NO_RESULT))
            out->counter = CryptCommit();
    } while(result == TPM_RC_NO_RESULT);

    return TPM_RC_SUCCESS;
}

#endif  // CC_EC_Ephemeral