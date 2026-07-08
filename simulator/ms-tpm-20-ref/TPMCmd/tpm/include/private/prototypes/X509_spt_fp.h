/*(Auto-generated)
 *  Created by TpmPrototypes; Version 3.0 July 18, 2017
 *  Date: Nov 14, 2019  Time: 05:57:02PM
 */

#ifndef _X509_SPT_FP_H_
#define _X509_SPT_FP_H_

//*** X509FindExtensionByOID()
// This will search a list of X509 extensions to find an extension with the
// requested OID. If the extension is found, the output context ('ctx') is set up
// to point to the OID in the extension.
//  Return Type: BOOL
//      TRUE(1)         success
//      FALSE(0)        failure (could be catastrophic)
BOOL X509FindExtensionByOID(ASN1UnmarshalContext* ctxIn,  // IN: the context to search
                            ASN1UnmarshalContext* ctx,  // OUT: the extension context
                            const BYTE*           OID   // IN: oid to search for
);

//*** X509GetExtensionBits()
// This function will extract a bit field from an extension. If the extension doesn't
// contain a bit string, it will fail.
// Return Type: BOOL
//  TRUE(1)         success
//  FALSE(0)        failure
UINT32
X509GetExtensionBits(ASN1UnmarshalContext* ctx, UINT32* value);

//***X509ProcessExtensions()
// This function is used to process the TPMA_OBJECT and KeyUsage extensions. It is not
// in the CertifyX509.c code because it makes the code harder to follow.
// Return Type: TPM_RC
//      TPM_RCS_ATTRIBUTES      the attributes of object are not consistent with
//                              the extension setting
//      TPM_RC_VALUE            problem parsing the extensions
TPM_RC
X509ProcessExtensions(
    OBJECT* object,       // IN: The object with the attributes to
                          //      check
    stringRef* extension  // IN: The start and length of the extensions
);

//*** X509AddSigningAlgorithm()
// This creates the singing algorithm data.
// Return Type: INT16
//  > 0                 number of octets added
// <= 0                 failure
INT16
X509AddSigningAlgorithm(
    ASN1MarshalContext* ctx, OBJECT* signKey, TPMT_SIG_SCHEME* scheme);

//*** X509AddPublicKey()
// This function will add the publicKey description to the DER data. If fillPtr is
// NULL, then no data is transferred and this function will indicate if the TPM
// has the values for DER-encoding of the public key.
//  Return Type: INT16
//      > 0         number of octets added
//      == 0        failure
INT16
X509AddPublicKey(ASN1MarshalContext* ctx, OBJECT* object);

//*** X509PushAlgorithmIdentifierSequence()
// The function adds the algorithm identifier sequence.
//  Return Type: INT16
//      > 0         number of bytes added
//     == 0         failure
INT16
X509PushAlgorithmIdentifierSequence(ASN1MarshalContext* ctx, const BYTE* OID);

#endif  // _X509_SPT_FP_H_
