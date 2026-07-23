#include "Tpm.h"
#include "HashSequenceStart_fp.h"

#if CC_HashSequenceStart  // Conditional expansion of this file

/*(See part 3 specification)
// Start a hash or an event sequence
*/
//  Return Type: TPM_RC
//      TPM_RC_OBJECT_MEMORY        no space to create an internal object
TPM_RC
TPM2_HashSequenceStart(HashSequenceStart_In*  in,  // IN: input parameter list
                       HashSequenceStart_Out* out  // OUT: output parameter list
)
{
    // Internal Data Update

    if(in->hashAlg == TPM_ALG_NULL)
        // Start a event sequence.  A TPM_RC_OBJECT_MEMORY error may be
        // returned at this point
        return ObjectCreateEventSequence(&in->auth, &out->sequenceHandle);

    // Start a hash sequence.  A TPM_RC_OBJECT_MEMORY error may be
    // returned at this point
    return ObjectCreateHashSequence(in->hashAlg, &in->auth, &out->sequenceHandle);
}

#endif  // CC_HashSequenceStart