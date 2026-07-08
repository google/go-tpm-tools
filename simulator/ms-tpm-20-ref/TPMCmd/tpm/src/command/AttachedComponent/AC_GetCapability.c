#include "Tpm.h"
#include "AC_GetCapability_fp.h"
#include "AC_spt_fp.h"

#if CC_AC_GetCapability  // Conditional expansion of this file

/*(See part 3 specification)
// This command returns various information regarding Attached Components
*/
TPM_RC
TPM2_AC_GetCapability(AC_GetCapability_In*  in,  // IN: input parameter list
                      AC_GetCapability_Out* out  // OUT: output parameter list
)
{
    // Command Output
    out->moreData =
        AcCapabilitiesGet(in->ac, in->capability, in->count, &out->capabilitiesData);

    return TPM_RC_SUCCESS;
}

#endif  // CC_AC_GetCapability