#include "Tpm.h"
#include "PolicyTransportSPDM_fp.h"

#if CC_PolicyTransportSPDM  // Conditional expansion of this file

/*(See part 3 specification)
// Add secure channel restrictions to the policyDigest
*/
//  Return Type: TPM_RC
//      TPM_RC_VALUE        TPM2_PolicyTransportSPDM has previously been executed
//      TPM_RC_HASH         hash algorithm in 'reqKeyName' or 'tpmKeyName' is not supported
//      TPM_RC_SIZE         'reqKeyName' or 'tpmKeyName' is not the correct size for its hash algorithm
TPM_RC
TPM2_PolicyTransportSPDM(PolicyTransportSPDM_In* in  // IN: input parameter list
)
{
    SESSION*     session;
    TPM_CC       commandCode = TPM_CC_PolicyTransportSPDM;
    TPM_ALG_ID   hashAlg;
    UINT16       digestSize;
    HASH_STATE   hashState;
    TPM2B_DIGEST scKeyNameHash;

    // Input Validation

    // Get pointer to the session structure
    session = SessionGet(in->policySession);

    // Check that TPM2_PolicyTransportSPDM has not previously been executed
    if(session->attributes.checkSecureChannel == SET)
        return TPM_RC_VALUE;

    // If 'reqKeyName' or 'tpmKeyName' are provided, check that they are valid Names
    if(in->reqKeyName.t.size != 0)
    {
        if(in->reqKeyName.t.size < 2)
        {
            return TPM_RCS_SIZE + RC_PolicyTransportSPDM_reqKeyName;
        }

        // Extract from the Name of the key, the algorithm used to compute its Name
        hashAlg = BYTE_ARRAY_TO_UINT16(in->reqKeyName.t.name);

        // 'reqKeyName' parameter must use a supported hash algorithm
        if(!CryptHashIsValidAlg(hashAlg, FALSE))
            return TPM_RCS_HASH + RC_PolicyTransportSPDM_reqKeyName;

        // and its size must be consistent with the hash algorithm
        digestSize = CryptHashGetDigestSize(hashAlg);
        if(digestSize != (in->reqKeyName.t.size - 2))
            return TPM_RCS_SIZE + RC_PolicyTransportSPDM_reqKeyName;
    }

    if(in->tpmKeyName.t.size != 0)
    {
        if(in->tpmKeyName.t.size < 2)
        {
            return TPM_RCS_SIZE + RC_PolicyTransportSPDM_tpmKeyName;
        }

        // Extract from the Name of the key, the algorithm used to compute its Name
        hashAlg = BYTE_ARRAY_TO_UINT16(in->tpmKeyName.t.name);

        // 'tpmKeyName' parameter must use a supported hash algorithm
        if(!CryptHashIsValidAlg(hashAlg, FALSE))
            return TPM_RCS_HASH + RC_PolicyTransportSPDM_tpmKeyName;

        // and its size must be consistent with the hash algorithm
        digestSize = CryptHashGetDigestSize(hashAlg);
        if(digestSize != (in->tpmKeyName.t.size - 2))
            return TPM_RCS_SIZE + RC_PolicyTransportSPDM_tpmKeyName;
    }

    // Internal Data Update
    if(in->reqKeyName.t.size != 0 || in->tpmKeyName.t.size != 0)
    {
        // Compute secure channel key name hash
        // scKeyNameHash = hash(reqKeyName.size || reqKeyName.name || tpmKeyName.size || tpmKeyName.name)
        //  Start hash
        scKeyNameHash.t.size = CryptHashStart(&hashState, session->authHashAlg);

        //  Add reqKeyName.size
        CryptDigestUpdateInt(&hashState, sizeof(UINT16), in->reqKeyName.t.size);

        //  Add reqKeyName.name (absent if Empty Buffer)
        CryptDigestUpdate2B(&hashState, &in->reqKeyName.b);

        //  Add tpmKeyName.size
        CryptDigestUpdateInt(&hashState, sizeof(UINT16), in->tpmKeyName.t.size);

        //  Add tpmKeyName.name (absent if Empty Buffer)
        CryptDigestUpdate2B(&hashState, &in->tpmKeyName.b);

        //  Complete digest
        CryptHashEnd2B(&hashState, &scKeyNameHash.b);

        // Update scKeyNameHash in session context
        session->scKeyNameHash = scKeyNameHash;
    }
    else
    {
        scKeyNameHash.t.size = 0;
    }

    // Update policy hash
    // policyDigestnew = hash(policyDigestold || TPM_CC_PolicyTransportSPDM || scKeyNameHash)
    //  Start hash
    session->u2.policyDigest.t.size =
        CryptHashStart(&hashState, session->authHashAlg);

    //  Add old digest
    CryptDigestUpdate2B(&hashState, &session->u2.policyDigest.b);

    //  Add commandCode
    CryptDigestUpdateInt(&hashState, sizeof(TPM_CC), commandCode);

    //  Add scKeyNameHash (absent if Empty Buffer)
    CryptDigestUpdate2B(&hashState, &scKeyNameHash.b);

    //  Complete the digest and get the results
    CryptHashEnd2B(&hashState, &session->u2.policyDigest.b);

    // Update session context
    session->attributes.checkSecureChannel = SET;
    if(in->reqKeyName.t.size != 0)
    {
        session->attributes.checkReqKey = SET;
    }
    if(in->tpmKeyName.t.size != 0)
    {
        session->attributes.checkTpmKey = SET;
    }

    return TPM_RC_SUCCESS;
}

#endif  // CC_PolicyTransportSPDM