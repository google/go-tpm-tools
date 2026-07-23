#include "Tpm.h"
#include "SetAlgorithmSet_fp.h"

#if CC_SetAlgorithmSet  // Conditional expansion of this file

/*(See part 3 specification)
// This command allows the platform to change the algorithm set setting of the TPM
*/
TPM_RC
TPM2_SetAlgorithmSet(SetAlgorithmSet_In* in  // IN: input parameter list
)
{
    // The command needs NV update.  Check if NV is available.
    // A TPM_RC_NV_UNAVAILABLE or TPM_RC_NV_RATE error may be returned at
    // this point
    RETURN_IF_NV_IS_NOT_AVAILABLE;

    // Internal Data Update
    gp.algorithmSet = in->algorithmSet;

    // Write the algorithm set changes to NV
    NV_SYNC_PERSISTENT(algorithmSet);

    return TPM_RC_SUCCESS;
}

#endif  // CC_SetAlgorithmSet