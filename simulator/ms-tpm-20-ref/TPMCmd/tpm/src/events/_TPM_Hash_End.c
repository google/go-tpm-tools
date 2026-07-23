#include "Tpm.h"

// This function is called to process a _TPM_Hash_End indication.
LIB_EXPORT BOOL _TPM_Hash_End(void)
{
    UINT32       i;
    TPM2B_DIGEST digest;
    HASH_OBJECT* hashObject;
    TPMI_DH_PCR  pcrHandle;

    // If the DRTM handle is not being used, then either _TPM_Hash_Start has not
    // been called, _TPM_Hash_End was previously called, or some other command
    // was executed and the sequence was aborted.
    if(g_DRTMHandle == TPM_RH_UNASSIGNED)
    {
        // do not enter failure mode because this is an ordering issue that
        // can be triggered by a BIOS issue, not an internal failure.
        return FALSE;
    }

    // Get DRTM sequence object
    hashObject = (HASH_OBJECT*)HandleToObject(g_DRTMHandle);
    pAssert_BOOL(hashObject != NULL);
    pAssert_BOOL(hashObject->attributes.eventSeq);

    // Is this _TPM_Hash_End after Startup or before
    if(TPMIsStarted())
    {
        // After

        // Reset the DRTM PCR
        PCRResetDynamics();

        // Extend the DRTM_PCR.
        pcrHandle = PCR_FIRST + DRTM_PCR;

        // DRTM sequence increments restartCount
        gr.restartCount++;
    }
    else
    {
        pcrHandle        = PCR_FIRST + HCRTM_PCR;
        g_DrtmPreStartup = TRUE;
    }

    // Complete hash and extend PCR, or if this is an HCRTM, complete
    // the hash, reset the H-CRTM register (PCR[0]) to 0...04, and then
    // extend the H-CRTM data
    for(i = 0; i < HASH_COUNT; i++)
    {
        TPMI_ALG_HASH hash = CryptHashGetAlgByIndex(i);
        // make sure that the PCR is implemented for this algorithm
        if(PcrIsAllocated(pcrHandle, hashObject->state.hashState[i].hashAlg))
        {
            // Complete hash
            digest.t.size = CryptHashGetDigestSize(hash);
            CryptHashEnd2B(&hashObject->state.hashState[i], &digest.b);

            PcrDrtm(pcrHandle, hash, &digest);
        }
    }

    // ensure g_DRTMHandle is cleared
    // and Flush sequence object
    TPMI_DH_OBJECT oldHandle = g_DRTMHandle;
    g_DRTMHandle             = TPM_RH_UNASSIGNED;
    return FlushObject(oldHandle);
}