#include "Tpm.h"
#include "FirmwareRead_fp.h"

#if CC_FirmwareRead  // Conditional expansion of this file

/*(See part 3 specification)
// FirmwareRead
*/
TPM_RC
TPM2_FirmwareRead(FirmwareRead_In*  in,  // IN: input parameter list
                  FirmwareRead_Out* out  // OUT: output parameter list
)
{
    // Not implemented
    UNUSED_PARAMETER(in);
    UNUSED_PARAMETER(out);
    return TPM_RC_SUCCESS;
}

#endif  // CC_FirmwareRead