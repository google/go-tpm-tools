#include "Tpm.h"
#include "Unseal_fp.h"

#if CC_Unseal  // Conditional expansion of this file

/*(See part 3 specification)
// return data in a sealed data blob
*/
//  Return Type: TPM_RC
//      TPM_RC_ATTRIBUTES         'itemHandle' has wrong attributes
//      TPM_RC_TYPE               'itemHandle' is not a KEYEDHASH data object
TPM_RC
TPM2_Unseal(Unseal_In* in, Unseal_Out* out)
{
    OBJECT* object;
    // Input Validation
    // Get pointer to loaded object
    object = HandleToObject(in->itemHandle);
    pAssert_RC(object != NULL);

    // Input handle must be a data object
    if(object->publicArea.type != TPM_ALG_KEYEDHASH)
        return TPM_RCS_TYPE + RC_Unseal_itemHandle;
    if(IS_ATTRIBUTE(object->publicArea.objectAttributes, TPMA_OBJECT, decrypt)
       || IS_ATTRIBUTE(object->publicArea.objectAttributes, TPMA_OBJECT, sign)
       || IS_ATTRIBUTE(object->publicArea.objectAttributes, TPMA_OBJECT, restricted))
        return TPM_RCS_ATTRIBUTES + RC_Unseal_itemHandle;
    // Command Output
    // Copy data
    out->outData = object->sensitive.sensitive.bits;
    return TPM_RC_SUCCESS;
}

#endif  // CC_Unseal