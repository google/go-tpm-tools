#include "Tpm.h"
#include "GetTestResult_fp.h"

#if CC_GetTestResult  // Conditional expansion of this file

/*(See part 3 specification)
// returns manufacturer-specific information regarding the results of a self-
// test and an indication of the test status.
*/

// In the reference implementation, this function is only reachable if the TPM is
// not in failure mode meaning that all tests that have been run have completed
// successfully. There is not test data and the test result is TPM_RC_SUCCESS.
TPM_RC
TPM2_GetTestResult(GetTestResult_Out* out  // OUT: output parameter list
)
{
    // Command Output

    // Call incremental self test function in crypt module
    out->testResult = CryptGetTestResult(&out->outData);

    return TPM_RC_SUCCESS;
}

#endif  // CC_GetTestResult