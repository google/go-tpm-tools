#include "Tpm.h"
#include "StirRandom_fp.h"

#if CC_StirRandom  // Conditional expansion of this file

/*(See part 3 specification)
// add entropy to the RNG state
*/
TPM_RC
TPM2_StirRandom(StirRandom_In* in  // IN: input parameter list
)
{
    // Internal Data Update
    CryptRandomStir(in->inData.t.size, in->inData.t.buffer);

    return TPM_RC_SUCCESS;
}

#endif  // CC_StirRandom