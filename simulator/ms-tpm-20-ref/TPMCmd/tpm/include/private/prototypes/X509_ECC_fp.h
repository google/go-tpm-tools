/*(Auto-generated)
 *  Created by TpmPrototypes; Version 3.0 July 18, 2017
 *  Date: Apr  2, 2019  Time: 11:00:49AM
 */

#ifndef _X509_ECC_FP_H_
#define _X509_ECC_FP_H_

//*** X509PushPoint()
// This seems like it might be used more than once so...
//  Return Type: INT16
//      > 0         number of bytes added
//     == 0         failure
INT16
X509PushPoint(ASN1MarshalContext* ctx, TPMS_ECC_POINT* p);

//*** X509AddSigningAlgorithmECC()
// This creates the singing algorithm data.
//  Return Type: INT16
//      > 0         number of bytes added
//     == 0         failure
INT16
X509AddSigningAlgorithmECC(
    OBJECT* signKey, TPMT_SIG_SCHEME* scheme, ASN1MarshalContext* ctx);

//*** X509AddPublicECC()
// This function will add the publicKey description to the DER data. If ctx is
// NULL, then no data is transferred and this function will indicate if the TPM
// has the values for DER-encoding of the public key.
//  Return Type: INT16
//      > 0         number of bytes added
//     == 0         failure
INT16
X509AddPublicECC(OBJECT* object, ASN1MarshalContext* ctx);

#endif  // _X509_ECC_FP_H_
