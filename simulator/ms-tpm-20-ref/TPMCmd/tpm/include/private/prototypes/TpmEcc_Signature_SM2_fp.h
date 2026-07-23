#ifndef _TPMECC_SIGNATURE_SM2_FP_H_
#define _TPMECC_SIGNATURE_SM2_FP_H_

#if ALG_ECC && ALG_SM2
//*** TpmEcc_SignEcSm2()
// This function signs a digest using the method defined in SM2 Part 2. The method
// in the standard will add a header to the message to be signed that is a hash of
// the values that define the key. This then hashed with the message to produce a
// digest ('e'). This function signs 'e'.
//  Return Type: TPM_RC
//      TPM_RC_VALUE         bad curve
TPM_RC TpmEcc_SignEcSm2(Crypt_Int* bnR,  // OUT: 'r' component of the signature
                        Crypt_Int* bnS,  // OUT: 's' component of the signature
                        const Crypt_EccCurve* E,    // IN: the curve used in signing
                        Crypt_Int*            bnD,  // IN: the private key
                        const TPM2B_DIGEST*   digest,  // IN: the digest to sign
                        RAND_STATE* rand  // IN: random number generator (mostly for
                                          //     debug)
);

//*** TpmEcc_ValidateSignatureEcSm2()
// This function is used to validate an SM2 signature.
//  Return Type: TPM_RC
//      TPM_RC_SIGNATURE            signature not valid
TPM_RC TpmEcc_ValidateSignatureEcSm2(
    Crypt_Int*            bnR,  // IN: 'r' component of the signature
    Crypt_Int*            bnS,  // IN: 's' component of the signature
    const Crypt_EccCurve* E,    // IN: the curve used in the signature
                                //     process
    Crypt_Point*        ecQ,    // IN: the public point of the key
    const TPM2B_DIGEST* digest  // IN: the digest that was signed
);

#endif  // ALG_ECC && ALG_SM2
#endif  // _TPMECC_SIGNATURE_SM2_FP_H_