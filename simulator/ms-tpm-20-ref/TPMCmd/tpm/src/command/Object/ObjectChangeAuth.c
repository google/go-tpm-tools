#include "Tpm.h"
#include "ObjectChangeAuth_fp.h"

#if CC_ObjectChangeAuth  // Conditional expansion of this file

#  include "Object_spt_fp.h"

/*(See part 3 specification)
// Create an object
*/
//  Return Type: TPM_RC
//      TPM_RC_SIZE             'newAuth' is larger than the size of the digest
//                              of the Name algorithm of 'objectHandle'
//      TPM_RC_TYPE             the key referenced by 'parentHandle' is not the
//                              parent of the object referenced by 'objectHandle';
//                              or 'objectHandle' is a sequence object.
TPM_RC
TPM2_ObjectChangeAuth(ObjectChangeAuth_In*  in,  // IN: input parameter list
                      ObjectChangeAuth_Out* out  // OUT: output parameter list
)
{
    TPMT_SENSITIVE sensitive;

    OBJECT*        object = HandleToObject(in->objectHandle);
    TPM2B_NAME     QNCompare;

    // Input Validation

    // Can not change authorization on sequence object
    if(ObjectIsSequence(object))
        return TPM_RCS_TYPE + RC_ObjectChangeAuth_objectHandle;

    // deliberately after ObjectIsSequence in case ObjectInSequence decides a
    // null object is a non-fatal error
    pAssert_RC(object != NULL);

    // Make sure that the authorization value is consistent with the nameAlg
    if(!AdjustAuthSize(&in->newAuth, object->publicArea.nameAlg))
        return TPM_RCS_SIZE + RC_ObjectChangeAuth_newAuth;

    // Parent handle should be the parent of object handle.  In this
    // implementation we verify this by checking the QN of object.  Other
    // implementation may choose different method to verify this attribute.
    ComputeQualifiedName(
        in->parentHandle, object->publicArea.nameAlg, &object->name, &QNCompare);
    if(!MemoryEqual2B(&object->qualifiedName.b, &QNCompare.b))
        return TPM_RCS_TYPE + RC_ObjectChangeAuth_parentHandle;

    // Command Output
    // Prepare the sensitive area with the new authorization value
    sensitive           = object->sensitive;
    sensitive.authValue = in->newAuth;

    // Protect the sensitive area
    return SensitiveToPrivate(&sensitive,
                              &object->name,
                              HandleToObject(in->parentHandle),
                              object->publicArea.nameAlg,
                              &out->outPrivate);
}

#endif  // CC_ObjectChangeAuth