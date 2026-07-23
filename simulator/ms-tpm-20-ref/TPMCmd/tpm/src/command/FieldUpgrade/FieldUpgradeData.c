#include "Tpm.h"
#include "FieldUpgradeData_fp.h"
#if CC_FieldUpgradeData  // Conditional expansion of this file

/*(See part 3 specification)
// FieldUpgradeData
*/
TPM_RC
TPM2_FieldUpgradeData(FieldUpgradeData_In*  in,  // IN: input parameter list
                      FieldUpgradeData_Out* out  // OUT: output parameter list
)
{
    // Not implemented
    UNUSED_PARAMETER(in);
    UNUSED_PARAMETER(out);
    return TPM_RC_SUCCESS;
}
#endif