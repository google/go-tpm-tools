//** Includes

#include "Tpm.h"
#include "Context_spt_fp.h"

//** Functions

//*** ComputeContextProtectionKey()
// This function retrieves the symmetric protection key for context encryption
// It is used by TPM2_ConextSave and TPM2_ContextLoad to create the symmetric
// encryption key and iv
/*(See part 1 specification)
    KDFa is used to generate the symmetric encryption key and IV. The parameters
    of the call are:
        Symkey = KDFa(hashAlg, hProof, vendorString, sequence, handle, bits)
    where
    hashAlg         a vendor-defined hash algorithm
    hProof          the hierarchy proof as selected by the hierarchy parameter
                    of the TPMS_CONTEXT
    vendorString    a value used to differentiate the uses of the KDF
    sequence        the sequence parameter of the TPMS_CONTEXT
    handle          the handle parameter of the TPMS_CONTEXT
    bits            the number of bits needed for a symmetric key and IV for
                    the context encryption
*/
//  Return Type: TPM_RC
//      TPM_RC_FW_LIMITED       The requested hierarchy is FW-limited, but the TPM
//                              does not support FW-limited objects or the TPM failed
//                              to derive the Firmware Secret.
//      TPM_RC_SVN_LIMITED      The requested hierarchy is SVN-limited, but the TPM
//                              does not support SVN-limited objects or the TPM
//                              failed to derive the Firmware SVN Secret for the
//                              requested SVN.
TPM_RC ComputeContextProtectionKey(TPMS_CONTEXT*  contextBlob,  // IN: context blob
                                   TPM2B_SYM_KEY* symKey,  // OUT: the symmetric key
                                   TPM2B_IV*      iv       // OUT: the IV.
)
{
    TPM_RC result = TPM_RC_SUCCESS;
    UINT16 symKeyBits;  // number of bits in the parent's
                        //   symmetric key
    TPM2B_PROOF proof;  // the proof value to use

    BYTE        kdfResult[sizeof(TPMU_HA) * 2];  // Value produced by the KDF

    TPM2B_DATA  sequence2B, handle2B;

    // Get sequence value in 2B format
    sequence2B.t.size = sizeof(contextBlob->sequence);
    MUST_BE(sizeof(contextBlob->sequence) <= sizeof(sequence2B.t.buffer));
    MemoryCopy(sequence2B.t.buffer, &contextBlob->sequence, sequence2B.t.size);

    // Get handle value in 2B format
    handle2B.t.size = sizeof(contextBlob->savedHandle);
    MUST_BE(sizeof(contextBlob->savedHandle) <= sizeof(handle2B.t.buffer));
    MemoryCopy(handle2B.t.buffer, &contextBlob->savedHandle, handle2B.t.size);

    // Get the symmetric encryption key size
    symKey->t.size = CONTEXT_ENCRYPT_KEY_BYTES;
    symKeyBits     = CONTEXT_ENCRYPT_KEY_BITS;
    // Get the size of the IV for the algorithm
    iv->t.size = CryptGetSymmetricBlockSize(CONTEXT_ENCRYPT_ALG, symKeyBits);

    // Get proof value
    result = HierarchyGetProof(contextBlob->hierarchy, &proof);
    if(result != TPM_RC_SUCCESS)
        return result;

    // KDFa to generate symmetric key and IV value
    CryptKDFa(CONTEXT_INTEGRITY_HASH_ALG,
              &proof.b,
              CONTEXT_KEY,
              &sequence2B.b,
              &handle2B.b,
              (symKey->t.size + iv->t.size) * 8,
              kdfResult,
              NULL,
              FALSE);

    MemorySet(proof.b.buffer, 0, proof.b.size);

    // Copy part of the returned value as the key
    pAssert_RC(symKey->t.size <= sizeof(symKey->t.buffer));
    MemoryCopy(symKey->t.buffer, kdfResult, symKey->t.size);

    // Copy the rest as the IV
    pAssert_RC(iv->t.size <= sizeof(iv->t.buffer));
    MemoryCopy(iv->t.buffer, &kdfResult[symKey->t.size], iv->t.size);

    return TPM_RC_SUCCESS;
}

//*** ComputeContextIntegrity()
// Generate the integrity hash for a context
//       It is used by TPM2_ContextSave to create an integrity hash
//       and by TPM2_ContextLoad to compare an integrity hash
/*(See part 1 specification)
    The HMAC integrity computation for a saved context is:
    HMACvendorAlg(hProof, resetValue {|| clearCount} || sequence || handle ||
                encContext)
    where
    HMACvendorAlg       HMAC using a vendor-defined hash algorithm
    hProof              the hierarchy proof as selected by the hierarchy
                        parameter of the TPMS_CONTEXT
    resetValue          either a counter value that increments on each TPM Reset
                        and is not reset over the lifetime of the TPM or a random
                        value that changes on each TPM Reset and has the size of
                        the digest produced by vendorAlg
    clearCount          a counter value that is incremented on each TPM Reset
                        or TPM Restart. This value is only included if the handle
                        value is 0x80000002.
    sequence            the sequence parameter of the TPMS_CONTEXT
    handle              the handle parameter of the TPMS_CONTEXT
    encContext          the encrypted context blob
*/
//  Return Type: TPM_RC
//      TPM_RC_FW_LIMITED       The requested hierarchy is FW-limited, but the TPM
//                              does not support FW-limited objects or the TPM failed
//                              to derive the Firmware Secret.
//      TPM_RC_SVN_LIMITED      The requested hierarchy is SVN-limited, but the TPM
//                              does not support SVN-limited objects or the TPM
//                              failed to derive the Firmware SVN Secret for the
//                              requested SVN.
TPM_RC ComputeContextIntegrity(TPMS_CONTEXT* contextBlob,  // IN: context blob
                               TPM2B_DIGEST* integrity     // OUT: integrity
)
{
    TPM_RC      result = TPM_RC_SUCCESS;
    HMAC_STATE  hmacState;
    TPM2B_PROOF proof;
    UINT16      integritySize;

    // Get proof value
    result = HierarchyGetProof(contextBlob->hierarchy, &proof);
    if(result != TPM_RC_SUCCESS)
        return result;

    // Start HMAC
    integrity->t.size =
        CryptHmacStart2B(&hmacState, CONTEXT_INTEGRITY_HASH_ALG, &proof.b);

    MemorySet(proof.b.buffer, 0, proof.b.size);

    // Compute integrity size at the beginning of context blob
    integritySize = sizeof(integrity->t.size) + integrity->t.size;

    // Adding total reset counter so that the context cannot be
    // used after a TPM Reset
    CryptDigestUpdateInt(
        &hmacState.hashState, sizeof(gp.totalResetCount), gp.totalResetCount);

    // If this is a ST_CLEAR object, add the clear count
    // so that this context cannot be loaded after a TPM Restart
    if(contextBlob->savedHandle == 0x80000002)
        CryptDigestUpdateInt(
            &hmacState.hashState, sizeof(gr.clearCount), gr.clearCount);

    // Adding sequence number to the HMAC to make sure that it doesn't
    // get changed
    CryptDigestUpdateInt(
        &hmacState.hashState, sizeof(contextBlob->sequence), contextBlob->sequence);

    // Protect the handle
    CryptDigestUpdateInt(&hmacState.hashState,
                         sizeof(contextBlob->savedHandle),
                         contextBlob->savedHandle);

    // Adding sensitive contextData, skip the leading integrity area
    CryptDigestUpdate(&hmacState.hashState,
                      contextBlob->contextBlob.t.size - integritySize,
                      contextBlob->contextBlob.t.buffer + integritySize);

    // Complete HMAC
    CryptHmacEnd2B(&hmacState, &integrity->b);

    return TPM_RC_SUCCESS;
}

//*** SequenceDataExport();
// This function is used scan through the sequence object and
// either modify the hash state data for export (contextSave) or to
// import it into the internal format (contextLoad).
// This function should only be called after the sequence object has been copied
// to the context buffer (contextSave) or from the context buffer into the sequence
// object. The presumption is that the context buffer version of the data is the
// same size as the internal representation so nothing outsize of the hash context
// area gets modified.
void SequenceDataExport(
    HASH_OBJECT*        object,       // IN: an internal hash object
    HASH_OBJECT_BUFFER* exportObject  // OUT: a sequence context in a buffer
)
{
    // If the hash object is not an event, then only one hash context is needed
    int count = (object->attributes.eventSeq) ? HASH_COUNT : 1;

    for(count--; count >= 0; count--)
    {
        HASH_STATE* hash       = &object->state.hashState[count];
        size_t      offset     = (BYTE*)hash - (BYTE*)object;
        BYTE*       exportHash = &((BYTE*)exportObject)[offset];

        CryptHashExportState(hash, (EXPORT_HASH_STATE*)exportHash);
    }
}

//*** SequenceDataImport();
// This function is used scan through the sequence object and
// either modify the hash state data for export (contextSave) or to
// import it into the internal format (contextLoad).
// This function should only be called after the sequence object has been copied
// to the context buffer (contextSave) or from the context buffer into the sequence
// object. The presumption is that the context buffer version of the data is the
// same size as the internal representation so nothing outsize of the hash context
// area gets modified.
void SequenceDataImport(
    HASH_OBJECT*        object,       // IN/OUT: an internal hash object
    HASH_OBJECT_BUFFER* exportObject  // IN/OUT: a sequence context in a buffer
)
{
    // If the hash object is not an event, then only one hash context is needed
    int count = (object->attributes.eventSeq) ? HASH_COUNT : 1;

    for(count--; count >= 0; count--)
    {
        HASH_STATE* hash       = &object->state.hashState[count];
        size_t      offset     = (BYTE*)hash - (BYTE*)object;
        BYTE*       importHash = &((BYTE*)exportObject)[offset];
        //
        CryptHashImportState(hash, (EXPORT_HASH_STATE*)importHash);
    }
}