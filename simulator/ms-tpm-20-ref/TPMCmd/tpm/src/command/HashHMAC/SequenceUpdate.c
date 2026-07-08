#include "Tpm.h"
#include "SequenceUpdate_fp.h"

#if CC_SequenceUpdate  // Conditional expansion of this file

/*(See part 3 specification)
// This function is used to add data to a sequence object.
*/
//  Return Type: TPM_RC
//      TPM_RC_MODE             'sequenceHandle' does not reference a hash or HMAC
//                              sequence object
TPM_RC
TPM2_SequenceUpdate(SequenceUpdate_In* in  // IN: input parameter list
)
{
    OBJECT*      object;
    HASH_OBJECT* hashObject;

    // Input Validation

    // Get sequence object pointer
    object     = HandleToObject(in->sequenceHandle);
    hashObject = (HASH_OBJECT*)object;

    // Check that referenced object is a sequence object.
    if(!ObjectIsSequence(object))
        return TPM_RCS_MODE + RC_SequenceUpdate_sequenceHandle;

    pAssert_RC(object != NULL);
    // Internal Data Update

    if(object->attributes.eventSeq == SET)
    {
        // Update event sequence object
        UINT32 i;
        for(i = 0; i < HASH_COUNT; i++)
        {
            // Update sequence object
            CryptDigestUpdate2B(&hashObject->state.hashState[i], &in->buffer.b);
        }
    }
    else
    {
        // Update hash/HMAC sequence object
        if(hashObject->attributes.hashSeq == SET)
        {
            // Is this the first block of the sequence
            if(hashObject->attributes.firstBlock == CLEAR)
            {
                // If so, indicate that first block was received
                hashObject->attributes.firstBlock = SET;

                // Check the first block to see if the first block can contain
                // the TPM_GENERATED_VALUE.  If it does, it is not safe for
                // a ticket.
                if(TicketIsSafe(&in->buffer.b))
                    hashObject->attributes.ticketSafe = SET;
            }
            // Update sequence object hash/HMAC stack
            CryptDigestUpdate2B(&hashObject->state.hashState[0], &in->buffer.b);
        }
        else if(object->attributes.hmacSeq == SET)
        {
            // Update sequence object HMAC stack
            CryptDigestUpdate2B(&hashObject->state.hmacState.hashState,
                                &in->buffer.b);
        }
    }
    return TPM_RC_SUCCESS;
}

#endif  // CC_SequenceUpdate