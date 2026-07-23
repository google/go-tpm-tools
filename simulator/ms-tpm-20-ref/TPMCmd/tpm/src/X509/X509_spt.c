//** Includes
#include "Tpm.h"
#include "TpmASN1.h"
#include "TpmASN1_fp.h"
#define _X509_SPT_
#include "X509.h"
#include "X509_spt_fp.h"
#if ALG_RSA
#  include "X509_RSA_fp.h"
#endif  // ALG_RSA
#if ALG_ECC
#  include "X509_ECC_fp.h"
#endif  // ALG_ECC
#if ALG_SM2
//#   include "X509_SM2_fp.h"
#endif  // ALG_RSA

#if CC_CertifyX509

//** Unmarshaling Functions

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
)
{
    INT16 length;
    //
    pAssert_BOOL(ctxIn != NULL);
    // Make the search non-destructive of the input if ctx provided. Otherwise, use
    // the provided context.
    if(ctx == NULL)
        ctx = ctxIn;
    // if the provided search context is different from the context of the extension,
    // then copy the search context to the search context.
    else if(ctx != ctxIn)
        *ctx = *ctxIn;
    // Now, search in the extension context
    for(; ctx->size > ctx->offset; ctx->offset += length)
    {
        GOTO_ERROR_UNLESS((length = ASN1NextTag(ctx)) >= 0);
        // If this is not a constructed sequence, then it doesn't belong
        // in the extensions.
        GOTO_ERROR_UNLESS(ctx->tag == ASN1_CONSTRUCTED_SEQUENCE);
        // Make sure that this entry could hold the OID
        if(length >= OID_SIZE(OID))
        {
            // See if this is a match for the provided object identifier.
            if(MemoryEqual(OID, &(ctx->buffer[ctx->offset]), OID_SIZE(OID)))
            {
                // Return with ' ctx' set to point to the start of the OID with the size
                // set to be the size of the SEQUENCE
                ctx->buffer += ctx->offset;
                ctx->offset = 0;
                ctx->size   = length;
                return TRUE;
            }
        }
    }
    GOTO_ERROR_UNLESS(ctx->offset == ctx->size);
    return FALSE;
Error:
    ctxIn->size = -1;
    ctx->size   = -1;
    return FALSE;
}

//*** X509GetExtensionBits()
// This function will extract a bit field from an extension. If the extension doesn't
// contain a bit string, it will fail.
// Return Type: BOOL
//  TRUE(1)         success
//  FALSE(0)        failure
UINT32
X509GetExtensionBits(ASN1UnmarshalContext* ctx, UINT32* value)
{
    INT16 length;
    //
    while(((length = ASN1NextTag(ctx)) > 0) && (ctx->size > ctx->offset))
    {
        // Since this is an extension, the extension value will be in an OCTET STRING
        if(ctx->tag == ASN1_OCTET_STRING)
        {
            return ASN1GetBitStringValue(ctx, value);
        }
        ctx->offset += length;
    }
    ctx->size = -1;
    return FALSE;
}

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
)
{
    ASN1UnmarshalContext ctx;
    ASN1UnmarshalContext extensionCtx;
    INT16                length;
    UINT32               value;
    TPMA_OBJECT          attributes = object->publicArea.objectAttributes;
    //
    if(!ASN1UnmarshalContextInitialize(&ctx, extension->len, extension->buf)
       || ((length = ASN1NextTag(&ctx)) < 0) || (ctx.tag != X509_EXTENSIONS))
        return TPM_RCS_VALUE;
    if(((length = ASN1NextTag(&ctx)) < 0) || (ctx.tag != (ASN1_CONSTRUCTED_SEQUENCE)))
        return TPM_RCS_VALUE;

    // Get the extension for the TPMA_OBJECT if there is one
    if(X509FindExtensionByOID(&ctx, &extensionCtx, OID_TCG_TPMA_OBJECT)
       && X509GetExtensionBits(&extensionCtx, &value))
    {
        // If an keyAttributes extension was found, it must be exactly the same as the
        // attributes of the object.
        // NOTE: MemoryEqual() is used rather than a simple UINT32 compare to avoid
        // type-punned pointer warning/error.
        if(!MemoryEqual(&value, &attributes, sizeof(value)))
            return TPM_RCS_ATTRIBUTES;
    }
    // Make sure the failure to find the value wasn't because of a fatal error
    else if(extensionCtx.size < 0)
        return TPM_RCS_VALUE;

    // Get the keyUsage extension. This one is required
    if(X509FindExtensionByOID(&ctx, &extensionCtx, OID_KEY_USAGE_EXTENSION)
       && X509GetExtensionBits(&extensionCtx, &value))
    {
        x509KeyUsageUnion keyUsage;
        BOOL              badSign;
        BOOL              badDecrypt;
        BOOL              badFixedTPM;
        BOOL              badRestricted;

        //
        keyUsage.integer = value;

        // see if any reserved bits are set
        if(keyUsage.integer & ~(TPMA_X509_KEY_USAGE_ALLOWED_BITS))
            return TPM_RCS_RESERVED_BITS;

        // For KeyUsage:
        // 1) 'sign' is SET if Key Usage includes signing
        badSign = ((KEY_USAGE_SIGN.integer & keyUsage.integer) != 0)
                  && !IS_ATTRIBUTE(attributes, TPMA_OBJECT, sign);
        // 2) 'decrypt' is SET if Key Usage includes decryption uses
        badDecrypt = ((KEY_USAGE_DECRYPT.integer & keyUsage.integer) != 0)
                     && !IS_ATTRIBUTE(attributes, TPMA_OBJECT, decrypt);
        // 3) 'fixedTPM' is SET if Key Usage is non-repudiation
        badFixedTPM = IS_ATTRIBUTE(keyUsage.x509, TPMA_X509_KEY_USAGE, nonrepudiation)
                      && !IS_ATTRIBUTE(attributes, TPMA_OBJECT, fixedTPM);
        // 4)'restricted' is SET if Key Usage is for key encipherment.
        badRestricted =
            IS_ATTRIBUTE(keyUsage.x509, TPMA_X509_KEY_USAGE, keyEncipherment)
            && !IS_ATTRIBUTE(attributes, TPMA_OBJECT, restricted);
        if(badSign || badDecrypt || badFixedTPM || badRestricted)
            return TPM_RCS_VALUE;
    }
    else
        // The KeyUsage extension is required
        return TPM_RCS_VALUE;

    return TPM_RC_SUCCESS;
}

//** Marshaling Functions

//*** X509AddSigningAlgorithm()
// This creates the singing algorithm data.
// Return Type: INT16
//  > 0                 number of octets added
// <= 0                 failure
INT16
X509AddSigningAlgorithm(
    ASN1MarshalContext* ctx, OBJECT* signKey, TPMT_SIG_SCHEME* scheme)
{
    switch(signKey->publicArea.type)
    {
#  if ALG_RSA
        case TPM_ALG_RSA:
            return X509AddSigningAlgorithmRSA(signKey, scheme, ctx);
#  endif  // ALG_RSA
#  if ALG_ECC
        case TPM_ALG_ECC:
            return X509AddSigningAlgorithmECC(signKey, scheme, ctx);
#  endif  // ALG_ECC
#  if ALG_SM2
        case TPM_ALG_SM2:
            break;  // no signing algorithm for SM2 yet
//            return X509AddSigningAlgorithmSM2(signKey, scheme, ctx);
#  endif  // ALG_SM2
        default:
            break;
    }
    return 0;
}

//*** X509AddPublicKey()
// This function will add the publicKey description to the DER data. If fillPtr is
// NULL, then no data is transferred and this function will indicate if the TPM
// has the values for DER-encoding of the public key.
//  Return Type: INT16
//      > 0         number of octets added
//      == 0        failure
INT16
X509AddPublicKey(ASN1MarshalContext* ctx, OBJECT* object)
{
    switch(object->publicArea.type)
    {
#  if ALG_RSA
        case TPM_ALG_RSA:
            return X509AddPublicRSA(object, ctx);
#  endif
#  if ALG_ECC
        case TPM_ALG_ECC:
            return X509AddPublicECC(object, ctx);
#  endif
#  if ALG_SM2
        case TPM_ALG_SM2:
            break;
#  endif
        default:
            break;
    }
    return FALSE;
}

//*** X509PushAlgorithmIdentifierSequence()
// The function adds the algorithm identifier sequence.
//  Return Type: INT16
//      > 0         number of bytes added
//     == 0         failure
INT16
X509PushAlgorithmIdentifierSequence(ASN1MarshalContext* ctx, const BYTE* OID)
{
    // An algorithm ID sequence is:
    //  SEQUENCE
    //      OID
    //      NULL
    ASN1StartMarshalContext(ctx);  // hash algorithm
    ASN1PushNull(ctx);
    ASN1PushOID(ctx, OID);
    return ASN1EndEncapsulation(ctx, ASN1_CONSTRUCTED_SEQUENCE);
}

#endif  // CC_CertifyX509
