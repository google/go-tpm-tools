#include "Tpm.h"
#include "PCR_Reset_fp.h"

#if CC_PCR_Reset  // Conditional expansion of this file

/*(See part 3 specification)
// Reset PCR
*/
//  Return Type: TPM_RC
//      TPM_RC_LOCALITY             current command locality is not allowed to
//                                  reset the PCR referenced by 'pcrHandle'
TPM_RC
TPM2_PCR_Reset(PCR_Reset_In* in  // IN: input parameter list
)
{
    // Input Validation

    // Check if the reset operation is allowed by the current command locality
    if(!PCRIsResetAllowed(in->pcrHandle))
        return TPM_RC_LOCALITY;

    // If PCR is state saved and we need to update orderlyState, check NV
    // availability
    if(PCRIsStateSaved(in->pcrHandle))
        RETURN_IF_ORDERLY;

    // Internal Data Update

    // Reset selected PCR in all banks to 0
    PCRSetValue(in->pcrHandle, 0);

    // Indicate that the PCR changed so that pcrCounter will be incremented if
    // necessary.
    PCRChanged(in->pcrHandle);

    return TPM_RC_SUCCESS;
}

#endif  // CC_PCR_Reset