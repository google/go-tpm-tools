#include "Tpm.h"
#include "Hash_fp.h"

#if CC_Hash  // Conditional expansion of this file

/*(See part 3 specification)
// Hash a data buffer
*/
TPM_RC
TPM2_Hash(Hash_In*  in,  // IN: input parameter list
          Hash_Out* out  // OUT: output parameter list
)
{
    HASH_STATE hashState;

    // Command Output

    // Output hash
    // Start hash stack
    out->outHash.t.size = CryptHashStart(&hashState, in->hashAlg);
    // Adding hash data
    CryptDigestUpdate2B(&hashState, &in->data.b);
    // Complete hash
    CryptHashEnd2B(&hashState, &out->outHash.b);

    // Output ticket
    out->validation.tag       = TPM_ST_HASHCHECK;
    out->validation.hierarchy = in->hierarchy;

    if(in->hierarchy == TPM_RH_NULL)
    {
        // Ticket is not required
        out->validation.hierarchy     = TPM_RH_NULL;
        out->validation.digest.t.size = 0;
    }
    else if(
        in->data.t.size >= sizeof(TPM_GENERATED_VALUE) && !TicketIsSafe(&in->data.b))
    {
        // Ticket is not safe
        out->validation.hierarchy     = TPM_RH_NULL;
        out->validation.digest.t.size = 0;
    }
    else
    {
        TPM_RC result;
        // Compute ticket
        result = TicketComputeHashCheck(
            in->hierarchy, in->hashAlg, &out->outHash, &out->validation);
        if(result != TPM_RC_SUCCESS)
            return result;
    }

    return TPM_RC_SUCCESS;
}

#endif  // CC_Hash