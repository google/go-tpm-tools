#include "Tpm.h"
#include "PCR_Read_fp.h"

#if CC_PCR_Read  // Conditional expansion of this file

/*(See part 3 specification)
// Read a set of PCR
*/
TPM_RC
TPM2_PCR_Read(PCR_Read_In*  in,  // IN: input parameter list
              PCR_Read_Out* out  // OUT: output parameter list
)
{
    // Command Output

    // Call PCR read function.  input pcrSelectionIn parameter could be changed
    // to reflect the actual PCR being returned
    TPM_RC result =
        PCRRead(&in->pcrSelectionIn, &out->pcrValues, &out->pcrUpdateCounter);
    if(result == TPM_RC_SUCCESS)
    {
        out->pcrSelectionOut = in->pcrSelectionIn;
    }

    return result;
}

#endif  // CC_PCR_Read