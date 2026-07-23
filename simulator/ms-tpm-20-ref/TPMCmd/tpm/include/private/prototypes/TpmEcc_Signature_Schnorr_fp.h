#ifndef _TPMECC_SIGNATURE_SCHNORR_FP_H_
#define _TPMECC_SIGNATURE_SCHNORR_FP_H_

#if ALG_ECC && ALG_ECSCHNORR
TPM_RC TpmEcc_SignEcSchnorr(
    Crypt_Int*            bnR,      // OUT: 'r' component of the signature
    Crypt_Int*            bnS,      // OUT: 's' component of the signature
    const Crypt_EccCurve* E,        // IN: the curve used in signing
    Crypt_Int*            bnD,      // IN: the signing key
    const TPM2B_DIGEST*   digest,   // IN: the digest to sign
    TPM_ALG_ID            hashAlg,  // IN: signing scheme (contains a hash)
    RAND_STATE*           rand      // IN: non-NULL when testing
);

//*** TpmEcc_ValidateSignatureEcSchnorr()
// This function is used to validate an EC Schnorr signature.
//  Return Type: TPM_RC
//      TPM_RC_SIGNATURE        signature not valid
TPM_RC TpmEcc_ValidateSignatureEcSchnorr(
    Crypt_Int*            bnR,      // IN: 'r' component of the signature
    Crypt_Int*            bnS,      // IN: 's' component of the signature
    TPM_ALG_ID            hashAlg,  // IN: hash algorithm of the signature
    const Crypt_EccCurve* E,        // IN: the curve used in the signature
                                    //     process
    Crypt_Point*        ecQ,        // IN: the public point of the key
    const TPM2B_DIGEST* digest      // IN: the digest that was signed
);

#endif  // ALG_ECC && ALG_ECSCHNORR
#endif  // _TPMECC_SIGNATURE_SCHNORR_FP_H_