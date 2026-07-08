#include "Tpm.h"
#include "IncrementalSelfTest_fp.h"

#if CC_IncrementalSelfTest  // Conditional expansion of this file

/*(See part 3 specification)
// perform a test of selected algorithms
*/
//  Return Type: TPM_RC
//      TPM_RC_CANCELED         the command was canceled (some tests may have
//                              completed)
//      TPM_RC_VALUE            an algorithm in the toTest list is not implemented
TPM_RC
TPM2_IncrementalSelfTest(IncrementalSelfTest_In*  in,  // IN: input parameter list
                         IncrementalSelfTest_Out* out  // OUT: output parameter list
)
{
    TPM_RC result;
    // Command Output

    // Call incremental self test function in crypt module. If this function
    // returns TPM_RC_VALUE, it means that an algorithm on the 'toTest' list is
    // not implemented.
    result = CryptIncrementalSelfTest(&in->toTest, &out->toDoList);
    if(result == TPM_RC_VALUE)
        return TPM_RCS_VALUE + RC_IncrementalSelfTest_toTest;
    return result;
}

#endif  // CC_IncrementalSelfTest