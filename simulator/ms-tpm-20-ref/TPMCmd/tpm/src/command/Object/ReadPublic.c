#include "Tpm.h"
#include "ReadPublic_fp.h"

#if CC_ReadPublic  // Conditional expansion of this file

/*(See part 3 specification)
// read public area of a loaded object
*/
//  Return Type: TPM_RC
//      TPM_RC_SEQUENCE             can not read the public area of a sequence
//                                  object
TPM_RC
TPM2_ReadPublic(ReadPublic_In*  in,  // IN: input parameter list
                ReadPublic_Out* out  // OUT: output parameter list
)
{
    OBJECT* object = HandleToObject(in->objectHandle);

    // Input Validation
    // Can not read public area of a sequence object
    if(ObjectIsSequence(object))
        return TPM_RC_SEQUENCE;

    // deliberately after ObjectIsSequence in case ObjectInSequence decides a
    // null object is a non-fatal error
    pAssert_RC(object != NULL);

    // Command Output
    out->outPublic.publicArea = object->publicArea;
    out->name                 = object->name;
    out->qualifiedName        = object->qualifiedName;

    return TPM_RC_SUCCESS;
}

#endif  // CC_ReadPublic