#include "Tpm.h"
#include "PCR_SetAuthValue_fp.h"

#if CC_PCR_SetAuthValue  // Conditional expansion of this file

/*(See part 3 specification)
// Set authValue to a group of PCR
*/
//  Return Type: TPM_RC
//      TPM_RC_VALUE                PCR referenced by 'pcrHandle' is not a member
//                                  of a PCR authorization group
TPM_RC
TPM2_PCR_SetAuthValue(PCR_SetAuthValue_In* in  // IN: input parameter list
)
{
    UINT32 groupIndex;
    // Input Validation:

    // If PCR does not belong to an auth group, return TPM_RC_VALUE
    if(!PCRBelongsAuthGroup(in->pcrHandle, &groupIndex))
        return TPM_RC_VALUE;

    // The command may cause the orderlyState to be cleared due to the update of
    // state clear data.  If this is the case, Check if NV is available.
    // A TPM_RC_NV_UNAVAILABLE or TPM_RC_NV_RATE error may be returned at
    // this point
    RETURN_IF_ORDERLY;

    // Internal Data Update

    // Set PCR authValue
    MemoryRemoveTrailingZeros(&in->auth);
    gc.pcrAuthValues.auth[groupIndex] = in->auth;

    return TPM_RC_SUCCESS;
}

#endif  // CC_PCR_SetAuthValue