/*(Auto-generated)
 *  Created by TpmPrototypes; Version 3.0 July 18, 2017
 *  Date: Apr  2, 2019  Time: 11:00:49AM
 */

#ifndef _X509_RSA_FP_H_
#define _X509_RSA_FP_H_

#if ALG_RSA

//*** X509AddSigningAlgorithmRSA()
// This creates the singing algorithm data.
//  Return Type: INT16
//      > 0         number of bytes added
//     == 0         failure
INT16
X509AddSigningAlgorithmRSA(
    OBJECT* signKey, TPMT_SIG_SCHEME* scheme, ASN1MarshalContext* ctx);

//*** X509AddPublicRSA()
// This function will add the publicKey description to the DER data. If fillPtr is
// NULL, then no data is transferred and this function will indicate if the TPM
// has the values for DER-encoding of the public key.
//  Return Type: INT16
//      > 0         number of bytes added
//     == 0         failure
INT16
X509AddPublicRSA(OBJECT* object, ASN1MarshalContext* ctx);
#endif  // ALG_RSA

#endif  // _X509_RSA_FP_H_
