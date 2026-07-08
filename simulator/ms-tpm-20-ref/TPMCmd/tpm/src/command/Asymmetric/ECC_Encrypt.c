#include "Tpm.h"
#include "ECC_Encrypt_fp.h"

#if CC_ECC_Encrypt  // Conditional expansion of this file

//  Return Type: TPM_RC
//      TPM_RC_ATTRIBUTES        key referenced by 'keyHandle' is restricted
//      TPM_RC_KEY                keyHandle does not reference an ECC key
//      TPM_RCS_SCHEME            bad scheme
TPM_RC
TPM2_ECC_Encrypt(ECC_Encrypt_In*  in,  // IN: input parameter list
                 ECC_Encrypt_Out* out  // OUT: output parameter list
)
{
    OBJECT* pubKey = HandleToObject(in->keyHandle);
    pAssert_RC(pubKey != NULL);

    // Parameter validation
    if(pubKey->publicArea.type != TPM_ALG_ECC)
        return TPM_RC_KEY + RC_ECC_Encrypt_keyHandle;
    // Have to have a scheme selected
    if(!CryptEccSelectScheme(pubKey, &in->inScheme))
        return TPM_RCS_SCHEME + RC_ECC_Encrypt_inScheme;
    //  Command Output
    return CryptEccEncrypt(
        pubKey, &in->inScheme, &in->plainText, &out->C1.point, &out->C2, &out->C3);
}

#endif  // CC_ECC_Encrypt