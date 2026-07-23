#include "Tpm.h"
#include "PCR_Allocate_fp.h"

#if CC_PCR_Allocate  // Conditional expansion of this file

/*(See part 3 specification)
// Allocate PCR banks
*/
//  Return Type: TPM_RC
//      TPM_RC_PCR              the allocation did not have required PCR
//      TPM_RC_NV_UNAVAILABLE   NV is not accessible
//      TPM_RC_NV_RATE          NV is in a rate-limiting mode
TPM_RC
TPM2_PCR_Allocate(PCR_Allocate_In*  in,  // IN: input parameter list
                  PCR_Allocate_Out* out  // OUT: output parameter list
)
{
    TPM_RC result;

    // The command needs NV update.  Check if NV is available.
    // A TPM_RC_NV_UNAVAILABLE or TPM_RC_NV_RATE error may be returned at
    // this point.
    // Note: These codes are not listed in the return values above because it is
    // an implementation choice to check in this routine rather than in a common
    // function that is called before these actions are called. These return values
    // are described in the Response Code section of Part 3.
    RETURN_IF_NV_IS_NOT_AVAILABLE;

    // Command Output

    // Call PCR Allocation function.
    result = PCRAllocate(
        &in->pcrAllocation, &out->maxPCR, &out->sizeNeeded, &out->sizeAvailable);
    if(result == TPM_RC_PCR)
        return result;

    //
    out->allocationSuccess = (result == TPM_RC_SUCCESS);

    // if re-configuration succeeds, set the flag to indicate PCR configuration is
    // going to be changed in next boot
    if(out->allocationSuccess == YES)
        g_pcrReConfig = TRUE;

    return TPM_RC_SUCCESS;
}

#endif  // CC_PCR_Allocate