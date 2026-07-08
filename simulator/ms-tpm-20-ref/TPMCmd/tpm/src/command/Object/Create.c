#include "Tpm.h"
#include "Object_spt_fp.h"
#include "Create_fp.h"

#if CC_Create  // Conditional expansion of this file

/*(See part 3 specification)
// Create a regular object
*/
//  Return Type: TPM_RC
//      TPM_RC_ATTRIBUTES       'sensitiveDataOrigin' is CLEAR when 'sensitive.data'
//                              is an Empty Buffer, or is SET when 'sensitive.data' is
//                              not empty;
//                              'fixedTPM', 'fixedParent', or 'encryptedDuplication'
//                              attributes are inconsistent between themselves or with
//                              those of the parent object;
//                              inconsistent 'restricted', 'decrypt' and 'sign'
//                              attributes;
//                              attempt to inject sensitive data for an asymmetric
//                              key;
//      TPM_RC_HASH             non-duplicable storage key and its parent have
//                              different name algorithm
//      TPM_RC_KDF              incorrect KDF specified for decrypting keyed hash
//                              object
//      TPM_RC_KEY              invalid key size values in an asymmetric key public
//                              area or a provided symmetric key has a value that is
//                              not allowed
//      TPM_RC_KEY_SIZE         key size in public area for symmetric key differs from
//                              the size in the sensitive creation area; may also be
//                              returned if the TPM does not allow the key size to be
//                              used for a Storage Key
//      TPM_RC_OBJECT_MEMORY    a free slot is not available as scratch memory for
//                              object creation
//      TPM_RC_RANGE            the exponent value of an RSA key is not supported.
//      TPM_RC_SCHEME           inconsistent attributes 'decrypt', 'sign', or
//                              'restricted' and key's scheme ID; or hash algorithm is
//                              inconsistent with the scheme ID for keyed hash object
//      TPM_RC_SIZE             size of public authPolicy or sensitive authValue does
//                              not match digest size of the name algorithm
//                              sensitive data size for the keyed hash object is
//                              larger than is allowed for the scheme
//      TPM_RC_SYMMETRIC        a storage key with no symmetric algorithm specified;
//                              or non-storage key with symmetric algorithm different
//                              from TPM_ALG_NULL
//      TPM_RC_TYPE             unknown object type;
//                              'parentHandle' does not reference a restricted
//                              decryption key in the storage hierarchy with both
//                              public and sensitive portion loaded
//      TPM_RC_VALUE            exponent is not prime or could not find a prime using
//                              the provided parameters for an RSA key;
//                              unsupported name algorithm for an ECC key
//      TPM_RC_OBJECT_MEMORY    there is no free slot for the object
TPM_RC
TPM2_Create(Create_In*  in,  // IN: input parameter list
            Create_Out* out  // OUT: output parameter list
)
{
    TPM_RC       result = TPM_RC_SUCCESS;
    OBJECT*      parentObject;
    OBJECT*      newObject;
    TPMT_PUBLIC* publicArea;

    // Input Validation
    parentObject = HandleToObject(in->parentHandle);
    pAssert_RC(parentObject != NULL);

    // Does parent have the proper attributes?
    if(!ObjectIsParent(parentObject))
        return TPM_RCS_TYPE + RC_Create_parentHandle;

    // Get a slot for the creation
    newObject = FindEmptyObjectSlot(NULL);
    if(newObject == NULL)
        return TPM_RC_OBJECT_MEMORY;
    // If the TPM2B_PUBLIC was passed as a structure, marshal it into is canonical
    // form for processing

    // to save typing.
    publicArea = &newObject->publicArea;

    // Copy the input structure to the allocated structure
    *publicArea = in->inPublic.publicArea;

    // Check attributes in input public area. CreateChecks() checks the things that
    // are unique to creation and then validates the attributes and values that are
    // common to create and load.
    result = CreateChecks(parentObject,
                          /* primaryHierarchy = */ 0,
                          publicArea,
                          in->inSensitive.sensitive.data.t.size);
    if(result != TPM_RC_SUCCESS)
        return RcSafeAddToResult(result, RC_Create_inPublic);
    // Clean up the authValue if necessary
    if(!AdjustAuthSize(&in->inSensitive.sensitive.userAuth, publicArea->nameAlg))
        return TPM_RCS_SIZE + RC_Create_inSensitive;

    // Command Output
    // Create the object using the default TPM random-number generator
    result = CryptCreateObject(newObject, &in->inSensitive.sensitive, NULL);
    if(result != TPM_RC_SUCCESS)
        return result;
    // Fill in creation data
    result = FillInCreationData(in->parentHandle,
                                publicArea->nameAlg,
                                &in->creationPCR,
                                &in->outsideInfo,
                                &out->creationData,
                                &out->creationHash);
    if(result != TPM_RC_SUCCESS)
        return result;

    // Compute creation ticket
    result = TicketComputeCreation(EntityGetHierarchy(in->parentHandle),
                                   &newObject->name,
                                   &out->creationHash,
                                   &out->creationTicket);
    if(result != TPM_RC_SUCCESS)
        return result;

    // Prepare output private data from sensitive
    result               = SensitiveToPrivate(&newObject->sensitive,
                                &newObject->name,
                                parentObject,
                                publicArea->nameAlg,
                                &out->outPrivate);

    newObject->hierarchy = parentObject->hierarchy;

    // Finish by copying the remaining return values
    out->outPublic.publicArea = newObject->publicArea;

    return result;
}

#endif  // CC_Create