//** Includes
#include "Tpm.h"
#include "X509.h"
#include "OIDs.h"
#include "TpmASN1_fp.h"
#include "X509_ECC_fp.h"
#include "X509_spt_fp.h"
#include "CryptHash_fp.h"

#if ALG_ECC && CC_CertifyX509

//** Functions

//*** X509PushPoint()
// This seems like it might be used more than once so...
//  Return Type: INT16
//      > 0         number of bytes added
//     == 0         failure
INT16
X509PushPoint(ASN1MarshalContext* ctx, TPMS_ECC_POINT* p)
{
    // Push a bit string containing the public key. For now, push the x, and y
    // coordinates of the public point, bottom up
    ASN1StartMarshalContext(ctx);  // BIT STRING
    {
        ASN1PushBytes(ctx, p->y.t.size, p->y.t.buffer);
        ASN1PushBytes(ctx, p->x.t.size, p->x.t.buffer);
        ASN1PushByte(ctx, 0x04);
    }
    return ASN1EndEncapsulation(ctx, ASN1_BITSTRING);  // Ends BIT STRING
}

//*** X509AddSigningAlgorithmECC()
// This creates the singing algorithm data.
//  Return Type: INT16
//      > 0         number of bytes added
//     == 0         failure
INT16
X509AddSigningAlgorithmECC(
    OBJECT* signKey, TPMT_SIG_SCHEME* scheme, ASN1MarshalContext* ctx)
{
    PHASH_DEF hashDef = CryptGetHashDef(scheme->details.any.hashAlg);
    //
    NOT_REFERENCED(signKey);
    // If the desired hashAlg definition wasn't found...
    if(hashDef->hashAlg != scheme->details.any.hashAlg)
        return 0;

    switch(scheme->scheme)
    {
#if ALG_ECDSA
        case TPM_ALG_ECDSA:
            // Make sure that we have an OID for this hash and ECC
            if((hashDef->ECDSA)[0] != ASN1_OBJECT_IDENTIFIER)
                break;
            // if this is just an implementation check, indicate that this
            // combination is supported
            if(!ctx)
                return 1;
            ASN1StartMarshalContext(ctx);
            ASN1PushOID(ctx, hashDef->ECDSA);
            return ASN1EndEncapsulation(ctx, ASN1_CONSTRUCTED_SEQUENCE);
#endif  //  ALG_ECDSA
        default:
            break;
    }
    return 0;
}

//*** X509AddPublicECC()
// This function will add the publicKey description to the DER data. If ctx is
// NULL, then no data is transferred and this function will indicate if the TPM
// has the values for DER-encoding of the public key.
//  Return Type: INT16
//      > 0         number of bytes added
//     == 0         failure
INT16
X509AddPublicECC(OBJECT* object, ASN1MarshalContext* ctx)
{
    const BYTE* curveOid =
        CryptEccGetOID(object->publicArea.parameters.eccDetail.curveID);
    if((curveOid == NULL) || (*curveOid != ASN1_OBJECT_IDENTIFIER))
        return 0;
    //
    //
    //  SEQUENCE (2 elem) 1st
    //    SEQUENCE (2 elem) 2nd
    //      OBJECT IDENTIFIER 1.2.840.10045.2.1 ecPublicKey (ANSI X9.62 public key type)
    //      OBJECT IDENTIFIER 1.2.840.10045.3.1.7 prime256v1 (ANSI X9.62 named curve)
    //    BIT STRING (520 bit) 000001001010000111010101010111001001101101000100000010...
    //
    // If this is a check to see if the key can be encoded, it can.
    // Need to mark the end sequence
    if(ctx == NULL)
        return 1;
    ASN1StartMarshalContext(ctx);  // SEQUENCE (2 elem) 1st
    {
        X509PushPoint(ctx, &object->publicArea.unique.ecc);  // BIT STRING
        ASN1StartMarshalContext(ctx);                        // SEQUENCE (2 elem) 2nd
        {
            ASN1PushOID(ctx, curveOid);        // curve dependent
            ASN1PushOID(ctx, OID_ECC_PUBLIC);  // (1.2.840.10045.2.1)
        }
        ASN1EndEncapsulation(ctx, ASN1_CONSTRUCTED_SEQUENCE);  // Ends SEQUENCE 2nd
    }
    return ASN1EndEncapsulation(ctx, ASN1_CONSTRUCTED_SEQUENCE);  // Ends SEQUENCE 1st
}

#endif // #if ALG_ECC && CC_CertifyX509
