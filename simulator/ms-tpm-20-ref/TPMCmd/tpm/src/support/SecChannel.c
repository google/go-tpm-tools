#include "Tpm.h"

#if SEC_CHANNEL_SUPPORT

// clang format turns this into one byte per line?! don't format this array.
// clang-format off

// Dummy requester key name
const TPM2B_NAME dummy_reqKeyName =
{{
    0x0032, // size
    // name
    {
        0x00, 0x0C, // hashAlg = TPM_ALG_SHA384
        // digest
        0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
        0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
        0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11
    }
}};

// clang-format on

//*** GetTpmSpdmPubKey()
// This function is used to get the dummy TPM SPDM public key
void GetTpmSpdmPubKey(TPMT_PUBLIC* tpmPubKey)
{
    tpmPubKey->type    = TPM_ALG_ECC;
    tpmPubKey->nameAlg = TPM_ALG_SHA384;
    tpmPubKey->objectAttributes =
        0x00050032;  // fixedTPM | fixedParent | sensitiveDataOrigin | restricted | sign;
    tpmPubKey->authPolicy.t.size                                 = 0;
    tpmPubKey->parameters.eccDetail.symmetric.algorithm          = TPM_ALG_NULL;
    tpmPubKey->parameters.eccDetail.scheme.scheme                = TPM_ALG_ECDSA;
    tpmPubKey->parameters.eccDetail.scheme.details.ecdsa.hashAlg = TPM_ALG_SHA384;
    tpmPubKey->parameters.eccDetail.curveID                      = TPM_ECC_NIST_P384;
    tpmPubKey->parameters.eccDetail.kdf.scheme                   = TPM_ALG_NULL;
    tpmPubKey->unique.ecc.x.t.size                               = 0x0030;
    tpmPubKey->unique.ecc.y.t.size                               = 0x0030;
    // For the dummy key, use x and y buffer all zeros
    memset(tpmPubKey->unique.ecc.x.t.buffer, 0, tpmPubKey->unique.ecc.x.t.size);
    memset(tpmPubKey->unique.ecc.y.t.buffer, 0, tpmPubKey->unique.ecc.y.t.size);
}

//*** SpdmCapGetTpmPubKeys()
// This function is used to get the 'TPM_PUB_KEY' public keys for GetCapability.
//  Return Type: TPMI_YES_NO
//  NO         no more properties to be reported
TPMI_YES_NO
SpdmCapGetTpmPubKeys(TPM_PUB_KEY spdmPubKey,  // IN: the starting TPM property
                     UINT32      count,  // IN: maximum number of returned properties
                     TPML_PUB_KEY* pubKeyList  // OUT: property list
)
{
    NOT_REFERENCED(spdmPubKey);
    NOT_REFERENCED(count);
    TPMI_YES_NO more = NO;

    // This reference implementation does not implement SPDM functionality and returns a single dummy TPM SPDM public key
    pubKeyList->count = 1;
    GetTpmSpdmPubKey(&pubKeyList->pubKeys[0].publicArea);
    pubKeyList->pubKeys[0].size = sizeof(TPMT_PUBLIC);

    return more;
}

//*** SpdmCapGetSessionInfo()
// This function is used to get the SPDM session information for GetCapability.
// This list has only one element.
//  Return Type: TPMI_YES_NO
//  NO         no more properties to be reported
TPMI_YES_NO
SpdmCapGetSessionInfo(
    TPML_SPDM_SESSION_INFO* spdmSessionInfoList  // OUT: property list
)
{
    TPMI_YES_NO more = NO;

    // This reference implementation does not implement SPDM messages
    // This function returns dummy SPDM session info
    TPMS_SPDM_SESSION_INFO* spdmSessionInfo =
        &spdmSessionInfoList->spdmSessionInfo[0];

    if(IsSpdmSessionActive(&spdmSessionInfo->reqKeyName,
                           &spdmSessionInfo->tpmKeyName))
        spdmSessionInfoList->count = 1;
    else
        // If GetCapability is not sent within an SPDM session, an Empty List is returned
        spdmSessionInfoList->count = 0;

    return more;
}

//*** IsSpdmSessionActive()
// This function indicates whether an SPDM session is active and if so,
// returns the  requester and TPM key names associated with the SPDM session.
//  Return Type: BOOL
//  TRUE(1)        SPDM session is active (TPM command is protected by an SPDM session)
BOOL IsSpdmSessionActive(
    TPM2B_NAME*
        reqKeyName,  // OUT: the requester key's name associated with the SPDM session
    TPM2B_NAME*
        tpmKeyName  // OUT: the TPM key's name associated with the SPDM session
)
{
    TPMT_PUBLIC tpmPubKey;

    // This reference implementation does not implement SPDM messages
    // This function returns always TRUE and returns dummy requester and TPM key names
    MemoryCopy2B(&reqKeyName->b, &dummy_reqKeyName.b, sizeof(dummy_reqKeyName));

    // Get TPM SPDM pub key and compute its name
    GetTpmSpdmPubKey(&tpmPubKey);
    PublicMarshalAndComputeName(&tpmPubKey, tpmKeyName);

    return TRUE;
}
#endif  // SEC_CHANNEL_SUPPORT
