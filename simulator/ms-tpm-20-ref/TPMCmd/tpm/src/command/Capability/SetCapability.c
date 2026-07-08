
#include "Tpm.h"
#include "SetCapability_fp.h"

#if CC_SetCapability  // Conditional expansion of this file

/*(See part 3 specification)
// This command allows configuration of the TPM's capabilities.
*/
//  Return Type: TPM_RC
//      TPM_RC_HANDLE       value of 'property' is in an unsupported handle range
//                          for the TPM_CAP_HANDLES 'capability' value
//      TPM_RC_VALUE        invalid 'capability'
TPM_RC
TPM2_SetCapability(SetCapability_In* in  // IN: input parameter list
)
{
    NOT_REFERENCED(in);
    // This reference implementation does not implement any settable capabilities.
    return TPM_RCS_VALUE + SetCapability_setCapabilityData;
}

#endif  // CC_SetCapability