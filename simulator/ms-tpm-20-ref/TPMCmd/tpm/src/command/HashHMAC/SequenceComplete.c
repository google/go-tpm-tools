#include "Tpm.h"
#include "SequenceComplete_fp.h"

#if CC_SequenceComplete  // Conditional expansion of this file

/*(See part 3 specification)
// Complete a sequence and flush the object.
*/
//  Return Type: TPM_RC
//      TPM_RC_MODE             'sequenceHandle' does not reference a hash or HMAC
//                              sequence object
TPM_RC
TPM2_SequenceComplete(SequenceComplete_In*  in,  // IN: input parameter list
                      SequenceComplete_Out* out  // OUT: output parameter list
)
{
    HASH_OBJECT* hashObject;
    // Input validation
    // Get hash object pointer
    hashObject = (HASH_OBJECT*)HandleToObject(in->sequenceHandle);
    pAssert_RC(hashObject != NULL);

    // input handle must be a hash or HMAC sequence object.
    if(hashObject->attributes.hashSeq == CLEAR
       && hashObject->attributes.hmacSeq == CLEAR)
        return TPM_RCS_MODE + RC_SequenceComplete_sequenceHandle;
    // Command Output
    if(hashObject->attributes.hashSeq == SET)  // sequence object for hash
    {
        // Get the hash algorithm before the algorithm is lost in CryptHashEnd
        TPM_ALG_ID hashAlg = hashObject->state.hashState[0].hashAlg;

        // Update last piece of the data
        CryptDigestUpdate2B(&hashObject->state.hashState[0], &in->buffer.b);

        // Complete hash
        out->result.t.size = CryptHashEnd(&hashObject->state.hashState[0],
                                          sizeof(out->result.t.buffer),
                                          out->result.t.buffer);
        // Check if the first block of the sequence has been received
        if(hashObject->attributes.firstBlock == CLEAR)
        {
            // If not, then this is the first block so see if it is 'safe'
            // to sign.
            if(TicketIsSafe(&in->buffer.b))
                hashObject->attributes.ticketSafe = SET;
        }
        // Output ticket
        out->validation.tag       = TPM_ST_HASHCHECK;
        out->validation.hierarchy = in->hierarchy;

        if(in->hierarchy == TPM_RH_NULL)
        {
            // Ticket is not required
            out->validation.digest.t.size = 0;
        }
        else if(hashObject->attributes.ticketSafe == CLEAR)
        {
            // Ticket is not safe to generate
            out->validation.hierarchy     = TPM_RH_NULL;
            out->validation.digest.t.size = 0;
        }
        else
        {
            TPM_RC result;
            // Compute ticket
            result = TicketComputeHashCheck(
                out->validation.hierarchy, hashAlg, &out->result, &out->validation);
            if(result != TPM_RC_SUCCESS)
                return result;
        }
    }
    else
    {
        //   Update last piece of data
        CryptDigestUpdate2B(&hashObject->state.hmacState.hashState, &in->buffer.b);
#  if !SMAC_IMPLEMENTED
        // Complete HMAC
        out->result.t.size = CryptHmacEnd(&(hashObject->state.hmacState),
                                          sizeof(out->result.t.buffer),
                                          out->result.t.buffer);
#  else
        // Complete the MAC
        out->result.t.size = CryptMacEnd(&hashObject->state.hmacState,
                                         sizeof(out->result.t.buffer),
                                         out->result.t.buffer);
#  endif
        // No ticket is generated for HMAC sequence
        out->validation.tag           = TPM_ST_HASHCHECK;
        out->validation.hierarchy     = TPM_RH_NULL;
        out->validation.digest.t.size = 0;
    }
    // Internal Data Update
    // mark sequence object as evict so it will be flushed on the way out
    hashObject->attributes.evict = SET;

    return TPM_RC_SUCCESS;
}

#endif  // CC_SequenceComplete