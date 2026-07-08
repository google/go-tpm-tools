#include "Tpm.h"
#include "PolicyGetDigest_fp.h"

#if CC_PolicyGetDigest  // Conditional expansion of this file

/*(See part 3 specification)
// returns the current policyDigest of the session
*/
TPM_RC
TPM2_PolicyGetDigest(PolicyGetDigest_In*  in,  // IN: input parameter list
                     PolicyGetDigest_Out* out  // OUT: output parameter list
)
{
    SESSION* session;

    // Command Output

    // Get pointer to the session structure
    session = SessionGet(in->policySession);
    pAssert_RC(session);

    out->policyDigest = session->u2.policyDigest;

    return TPM_RC_SUCCESS;
}

#endif  // CC_PolicyGetDigest