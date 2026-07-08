#include "Tpm.h"
#include "PCR_Event_fp.h"

#if CC_PCR_Event  // Conditional expansion of this file

/*(See part 3 specification)
// Update PCR
*/
//  Return Type: TPM_RC
//      TPM_RC_LOCALITY             current command locality is not allowed to
//                                  extend the PCR referenced by 'pcrHandle'
TPM_RC
TPM2_PCR_Event(PCR_Event_In*  in,  // IN: input parameter list
               PCR_Event_Out* out  // OUT: output parameter list
)
{
    HASH_STATE hashState;
    UINT32     i;
    UINT16     size;

    // Input Validation

    // If a PCR extend is required
    if(in->pcrHandle != TPM_RH_NULL)
    {
        // If the PCR is not allow to extend, return error
        if(!PCRIsExtendAllowed(in->pcrHandle))
            return TPM_RC_LOCALITY;

        // If PCR is state saved and we need to update orderlyState, check NV
        // availability
        if(PCRIsStateSaved(in->pcrHandle))
            RETURN_IF_ORDERLY;
    }

    // Internal Data Update

    out->digests.count = HASH_COUNT;

    // Iterate supported PCR bank algorithms to extend
    for(i = 0; i < HASH_COUNT; i++)
    {
        TPM_ALG_ID hash                 = CryptHashGetAlgByIndex(i);
        out->digests.digests[i].hashAlg = hash;
        size                            = CryptHashStart(&hashState, hash);
        CryptDigestUpdate2B(&hashState, &in->eventData.b);
        CryptHashEnd(&hashState, size, (BYTE*)&out->digests.digests[i].digest);
        if(in->pcrHandle != TPM_RH_NULL)
            PCRExtend(
                in->pcrHandle, hash, size, (BYTE*)&out->digests.digests[i].digest);
    }

    return TPM_RC_SUCCESS;
}

#endif  // CC_PCR_Event