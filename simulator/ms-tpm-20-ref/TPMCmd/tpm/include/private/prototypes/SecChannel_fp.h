#ifndef _SEC_CHANNEL_FP_H_
#define _SEC_CHANNEL_FP_H_

//*** GetTpmSpdmPubKey()
// This function is used to get the dummy TPM SPDM public key
void GetTpmSpdmPubKey(TPMT_PUBLIC* tpmPubKey);

//*** SpdmCapGetTpmPubKeys()
// This function is used to get the 'TPM_PUB_KEY' public keys for GetCapability.
//  Return Type: TPMI_YES_NO
//  NO         no more properties to be reported
TPMI_YES_NO
SpdmCapGetTpmPubKeys(TPM_PUB_KEY spdmPubKey,  // IN: the starting TPM property
                     UINT32      count,  // IN: maximum number of returned properties
                     TPML_PUB_KEY* pubKeyList  // OUT: property list
);

//*** SpdmCapGetSessionInfo()
// This function is used to get the SPDM session information for GetCapability.
//  Return Type: TPMI_YES_NO
//  NO         no more properties to be reported
TPMI_YES_NO
SpdmCapGetSessionInfo(
    TPML_SPDM_SESSION_INFO* spdmSessionInfoList  // OUT: property list
);

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
);

#endif  // _SEC_CHANNEL_FP_H_