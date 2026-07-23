#include "Tpm.h"
#include "TestParms_fp.h"

#if CC_TestParms  // Conditional expansion of this file

/*(See part 3 specification)
// TestParms
*/
TPM_RC
TPM2_TestParms(TestParms_In* in  // IN: input parameter list
)
{
    // Input parameter is not reference in command action
    NOT_REFERENCED(in);

    // The parameters are tested at unmarshal process.  We do nothing in command
    // action
    return TPM_RC_SUCCESS;
}

#endif  // CC_TestParms