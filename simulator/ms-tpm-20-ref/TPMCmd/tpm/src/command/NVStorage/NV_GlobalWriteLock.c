#include "Tpm.h"
#include "NV_GlobalWriteLock_fp.h"

#if CC_NV_GlobalWriteLock  // Conditional expansion of this file

/*(See part 3 specification)
// Set global write lock for NV index
*/
TPM_RC
TPM2_NV_GlobalWriteLock(NV_GlobalWriteLock_In* in  // IN: input parameter list
)
{
    // Input parameter (the authorization handle) is not reference in command action.
    NOT_REFERENCED(in);

    // Internal Data Update

    // Implementation dependent method of setting the global lock
    return NvSetGlobalLock();
}

#endif  // CC_NV_GlobalWriteLock