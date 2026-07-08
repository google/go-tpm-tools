#include "Tpm.h"
#include "ECC_Parameters_fp.h"

#if CC_ECC_Parameters  // Conditional expansion of this file

/*(See part 3 specification)
// This command returns the parameters of an ECC curve identified by its TCG
// assigned curveID
*/
//  Return Type: TPM_RC
//      TPM_RC_VALUE                    Unsupported ECC curve ID
TPM_RC
TPM2_ECC_Parameters(ECC_Parameters_In*  in,  // IN: input parameter list
                    ECC_Parameters_Out* out  // OUT: output parameter list
)
{
    // Command Output

    // Get ECC curve parameters
    if(CryptEccGetParameters(in->curveID, &out->parameters))
        return TPM_RC_SUCCESS;
    else
        return TPM_RCS_VALUE + RC_ECC_Parameters_curveID;
}

#endif  // CC_ECC_Parameters