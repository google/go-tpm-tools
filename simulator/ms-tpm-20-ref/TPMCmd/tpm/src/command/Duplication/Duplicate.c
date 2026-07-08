#include "Tpm.h"
#include "Duplicate_fp.h"

#if CC_Duplicate  // Conditional expansion of this file

#  include "Object_spt_fp.h"

/*(See part 3 specification)
// Duplicate a loaded object
*/
//  Return Type: TPM_RC
//      TPM_RC_ATTRIBUTES   key to duplicate has 'fixedParent' SET
//      TPM_RC_HASH         for an RSA key, the nameAlg digest size for the
//                          newParent is not compatible with the key size
//      TPM_RC_HIERARCHY    'encryptedDuplication' is SET and 'newParentHandle'
//                          specifies Null Hierarchy
//      TPM_RC_KEY          'newParentHandle' references invalid ECC key (public
//                          point not on the curve)
//      TPM_RC_SIZE         input encryption key size does not match the
//                          size specified in symmetric algorithm
//      TPM_RC_SYMMETRIC    'encryptedDuplication' is SET but no symmetric
//                          algorithm is provided
//      TPM_RC_TYPE         'newParentHandle' is neither a storage key nor
//                          TPM_RH_NULL; or the object has a NULL nameAlg
//      TPM_RC_VALUE        for an RSA newParent, the sizes of the digest and
//                          the encryption key are too large to be OAEP encoded
TPM_RC
TPM2_Duplicate(Duplicate_In*  in,  // IN: input parameter list
               Duplicate_Out* out  // OUT: output parameter list
)
{
    TPM_RC         result = TPM_RC_SUCCESS;
    TPMT_SENSITIVE sensitive;

    UINT16         innerKeySize = 0;  // encrypt key size for inner wrap

    OBJECT*        object;
    OBJECT*        newParent;
    TPM2B_DATA     data;

    // Input Validation

    // Get duplicate object pointer
    object = HandleToObject(in->objectHandle);
    pAssert_RC(object != NULL);

    // Get new parent
    newParent = HandleToObject(in->newParentHandle);

    // duplicate key must have fixParent bit CLEAR.
    if(IS_ATTRIBUTE(object->publicArea.objectAttributes, TPMA_OBJECT, fixedParent))
        return TPM_RCS_ATTRIBUTES + RC_Duplicate_objectHandle;

    // Do not duplicate object with NULL nameAlg
    if(object->publicArea.nameAlg == TPM_ALG_NULL)
        return TPM_RCS_TYPE + RC_Duplicate_objectHandle;

    // new parent key must be a storage object or TPM_RH_NULL
    if(in->newParentHandle != TPM_RH_NULL && !ObjectIsStorage(in->newParentHandle))
        return TPM_RCS_TYPE + RC_Duplicate_newParentHandle;

    // If the duplicated object has encryptedDuplication SET, then there must be
    // an inner wrapper and the new parent may not be TPM_RH_NULL
    if(IS_ATTRIBUTE(
           object->publicArea.objectAttributes, TPMA_OBJECT, encryptedDuplication))
    {
        if(in->symmetricAlg.algorithm == TPM_ALG_NULL)
            return TPM_RCS_SYMMETRIC + RC_Duplicate_symmetricAlg;
        if(in->newParentHandle == TPM_RH_NULL)
            return TPM_RCS_HIERARCHY + RC_Duplicate_newParentHandle;
    }

    if(in->symmetricAlg.algorithm == TPM_ALG_NULL)
    {
        // if algorithm is TPM_ALG_NULL, input key size must be 0
        if(in->encryptionKeyIn.t.size != 0)
            return TPM_RCS_SIZE + RC_Duplicate_encryptionKeyIn;
    }
    else
    {
        // Get inner wrap key size
        innerKeySize = in->symmetricAlg.keyBits.sym;

        // If provided the input symmetric key must match the size of the algorithm
        if(in->encryptionKeyIn.t.size != 0
           && in->encryptionKeyIn.t.size != (innerKeySize + 7) / 8)
            return TPM_RCS_SIZE + RC_Duplicate_encryptionKeyIn;
    }

    // Command Output

    if(in->newParentHandle != TPM_RH_NULL)
    {
        // Make encrypt key and its associated secret structure.  A TPM_RC_KEY
        // error may be returned at this point
        out->outSymSeed.t.size = sizeof(out->outSymSeed.t.secret);
        result =
            CryptSecretEncrypt(newParent, DUPLICATE_STRING, &data, &out->outSymSeed);
        if(result != TPM_RC_SUCCESS)
            return result;
    }
    else
    {
        // Do not apply outer wrapper
        data.t.size            = 0;
        out->outSymSeed.t.size = 0;
    }

    // Copy sensitive area
    sensitive = object->sensitive;

    // Prepare output private data from sensitive.
    // Note: If there is no encryption key, one will be provided by
    // SensitiveToDuplicate(). This is why the assignment of encryptionKeyIn to
    // encryptionKeyOut will work properly and is not conditional.
    result                = SensitiveToDuplicate(&sensitive,
                                  &object->name.b,
                                  newParent,
                                  object->publicArea.nameAlg,
                                  &data.b,
                                  &in->symmetricAlg,
                                  &in->encryptionKeyIn,
                                  &out->duplicate);

    out->encryptionKeyOut = in->encryptionKeyIn;

    return result;
}

#endif  // CC_Duplicate