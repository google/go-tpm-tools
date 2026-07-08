#include "Tpm.h"
#include "GetRandom_fp.h"

#if CC_GetRandom  // Conditional expansion of this file

/*(See part 3 specification)
// random number generator
*/
TPM_RC
TPM2_GetRandom(GetRandom_In*  in,  // IN: input parameter list
               GetRandom_Out* out  // OUT: output parameter list
)
{
    // Command Output

    // if the requested bytes exceed the output buffer size, generates the
    // maximum bytes that the output buffer allows
    if(in->bytesRequested > sizeof(TPMU_HA))
        out->randomBytes.t.size = sizeof(TPMU_HA);
    else
        out->randomBytes.t.size = in->bytesRequested;

    CryptRandomGenerate(out->randomBytes.t.size, out->randomBytes.t.buffer);

    return TPM_RC_SUCCESS;
}

#endif  // CC_GetRandom