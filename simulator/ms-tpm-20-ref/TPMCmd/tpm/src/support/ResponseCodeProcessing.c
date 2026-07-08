//** Description
// This file contains the miscellaneous functions for processing response codes.
// NOTE: Currently, there is only one.

//** Includes and Defines
#include "Tpm.h"

//** RcSafeAddToResult()
// Adds a modifier to a response code as long as the response code allows a modifier
// and no modifier has already been added.
TPM_RC
RcSafeAddToResult(TPM_RC responseCode, TPM_RC modifier)
{
    if((responseCode & RC_FMT1) && !(responseCode & 0xf40))
        return responseCode + modifier;
    else
        return responseCode;
}
