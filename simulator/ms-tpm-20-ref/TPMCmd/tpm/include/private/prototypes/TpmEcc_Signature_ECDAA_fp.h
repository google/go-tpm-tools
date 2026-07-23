#ifndef _TPMECC_SIGNATURE_ECDAA_FP_H_
#define _TPMECC_SIGNATURE_ECDAA_FP_H_
#if ALG_ECC && ALG_ECDAA

//*** TpmEcc_SignEcdaa()
//
// This function performs 's' = 'r' + 'T' * 'd' mod 'q' where
// 1) 'r' is a random, or pseudo-random value created in the commit phase
// 2) 'nonceK' is a TPM-generated, random value 0 < 'nonceK' < 'n'
// 3) 'T' is mod 'q' of "Hash"('nonceK' || 'digest'), and
// 4) 'd' is a private key.
//
// The signature is the tuple ('nonceK', 's')
//
// Regrettably, the parameters in this function kind of collide with the parameter
// names used in ECSCHNORR making for a lot of confusion.
//  Return Type: TPM_RC
//      TPM_RC_SCHEME       unsupported hash algorithm
//      TPM_RC_NO_RESULT    cannot get values from random number generator
TPM_RC TpmEcc_SignEcdaa(
    TPM2B_ECC_PARAMETER*  nonceK,  // OUT: 'nonce' component of the signature
    Crypt_Int*            bnS,     // OUT: 's' component of the signature
    const Crypt_EccCurve* E,       // IN: the curve used in signing
    Crypt_Int*            bnD,     // IN: the private key
    const TPM2B_DIGEST*   digest,  // IN: the value to sign (mod 'q')
    TPMT_ECC_SCHEME*      scheme,  // IN: signing scheme (contains the
                                   //      commit count value).
    OBJECT*     eccKey,            // IN: The signing key
    RAND_STATE* rand               // IN: a random number state
);

#endif  // ALG_ECC && ALG_ECDAA
#endif  // _TPMECC_SIGNATURE_ECDAA_FP_H_