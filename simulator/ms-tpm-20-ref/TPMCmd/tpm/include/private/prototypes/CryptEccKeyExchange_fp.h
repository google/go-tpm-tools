/*(Auto-generated)
 *  Created by TpmPrototypes; Version 3.0 July 18, 2017
 *  Date: Mar 28, 2019  Time: 08:25:18PM
 */

#ifndef _CRYPT_ECC_KEY_EXCHANGE_FP_H_
#define _CRYPT_ECC_KEY_EXCHANGE_FP_H_

#if CC_ZGen_2Phase == YES

//*** CryptEcc2PhaseKeyExchange()
// This function is the dispatch routine for the EC key exchange functions that use
// two ephemeral and two static keys.
//  Return Type: TPM_RC
//      TPM_RC_SCHEME             scheme is not defined
LIB_EXPORT TPM_RC CryptEcc2PhaseKeyExchange(
    TPMS_ECC_POINT*      outZ1,    // OUT: a computed point
    TPMS_ECC_POINT*      outZ2,    // OUT: and optional second point
    TPM_ECC_CURVE        curveId,  // IN: the curve for the computations
    TPM_ALG_ID           scheme,   // IN: the key exchange scheme
    TPM2B_ECC_PARAMETER* dsA,      // IN: static private TPM key
    TPM2B_ECC_PARAMETER* deA,      // IN: ephemeral private TPM key
    TPMS_ECC_POINT*      QsB,      // IN: static public party B key
    TPMS_ECC_POINT*      QeB       // IN: ephemeral public party B key
);
#  if ALG_SM2

//*** SM2KeyExchange()
// This function performs the key exchange defined in SM2.
// The first step is to compute
//  'tA' = ('dsA' + 'deA'  avf(Xe,A)) mod 'n'
// Then, compute the 'Z' value from
// 'outZ' = ('h'  'tA' mod 'n') ('QsA' + [avf('QeB.x')]('QeB')).
// The function will compute the ephemeral public key from the ephemeral
// private key.
// All points are required to be on the curve of 'inQsA'. The function will fail
// catastrophically if this is not the case
//  Return Type: TPM_RC
//      TPM_RC_NO_RESULT        the value for dsA does not give a valid point on the
//                              curve
LIB_EXPORT TPM_RC SM2KeyExchange(
    TPMS_ECC_POINT*      outZ,     // OUT: the computed point
    TPM_ECC_CURVE        curveId,  // IN: the curve for the computations
    TPM2B_ECC_PARAMETER* dsAIn,    // IN: static private TPM key
    TPM2B_ECC_PARAMETER* deAIn,    // IN: ephemeral private TPM key
    TPMS_ECC_POINT*      QsBIn,    // IN: static public party B key
    TPMS_ECC_POINT*      QeBIn     // IN: ephemeral public party B key
);
#  endif
#endif  // CC_ZGen_2Phase

#endif  // _CRYPT_ECC_KEY_EXCHANGE_FP_H_
