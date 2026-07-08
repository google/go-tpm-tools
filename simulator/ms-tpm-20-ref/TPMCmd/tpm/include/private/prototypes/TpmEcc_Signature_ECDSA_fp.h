#ifndef _TPMECC_SIGNATURE_ECDSA_FP_H_
#define _TPMECC_SIGNATURE_ECDSA_FP_H_

#if ALG_ECC && ALG_ECDSA
#  include <private/CryptRand.h>

//*** TpmEcc_SignEcdsa()
// This function implements the ECDSA signing algorithm. The method is described
// in the comments below.
TPM_RC
TpmEcc_SignEcdsa(Crypt_Int*            bnR,   // OUT: 'r' component of the signature
                 Crypt_Int*            bnS,   // OUT: 's' component of the signature
                 const Crypt_EccCurve* E,     // IN: the curve used in the signature
                                              //     process
                 Crypt_Int*          bnD,     // IN: private signing key
                 const TPM2B_DIGEST* digest,  // IN: the digest to sign
                 RAND_STATE*         rand     // IN: used in debug of signing
);

//*** TpmEcc_ValidateSignatureEcdsa()
// This function validates an ECDSA signature. rIn and sIn should have been checked
// to make sure that they are in the range 0 < 'v' < 'n'
//  Return Type: TPM_RC
//      TPM_RC_SIGNATURE           signature not valid
TPM_RC
TpmEcc_ValidateSignatureEcdsa(
    Crypt_Int*            bnR,  // IN: 'r' component of the signature
    Crypt_Int*            bnS,  // IN: 's' component of the signature
    const Crypt_EccCurve* E,    // IN: the curve used in the signature
                                //     process
    const Crypt_Point*  ecQ,    // IN: the public point of the key
    const TPM2B_DIGEST* digest  // IN: the digest that was signed
);

#endif  // ALG_ECC && ALG_ECDSA
#endif  // _TPMECC_SIGNATURE_ECDSA_FP_H_