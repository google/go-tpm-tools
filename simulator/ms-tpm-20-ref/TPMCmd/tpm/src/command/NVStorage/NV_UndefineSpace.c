#include "Tpm.h"
#include "NV_UndefineSpace_fp.h"

#if CC_NV_UndefineSpace  // Conditional expansion of this file

/*(See part 3 specification)
// Delete an NV Index
*/
//  Return Type: TPM_RC
//      TPM_RC_ATTRIBUTES               TPMA_NV_POLICY_DELETE is SET in the Index
//                                      referenced by 'nvIndex' so this command may
//                                      not be used to delete this Index (see
//                                      TPM2_NV_UndefineSpaceSpecial())
//      TPM_RC_NV_AUTHORIZATION         attempt to use ownerAuth to delete an index
//                                      created by the platform
//
TPM_RC
TPM2_NV_UndefineSpace(NV_UndefineSpace_In* in  // IN: input parameter list
)
{
    NV_REF    locator;
    NV_INDEX* nvIndex = NvGetIndexInfo(in->nvIndex, &locator);

    // Input Validation
    // This command can't be used to delete an index with TPMA_NV_POLICY_DELETE SET
    if(IS_ATTRIBUTE(nvIndex->publicArea.attributes, TPMA_NV, POLICY_DELETE))
        return TPM_RCS_ATTRIBUTES + RC_NV_UndefineSpace_nvIndex;

    // The owner may only delete an index that was defined with ownerAuth. The
    // platform may delete an index that was created with either authorization.
    if(in->authHandle == TPM_RH_OWNER
       && IS_ATTRIBUTE(nvIndex->publicArea.attributes, TPMA_NV, PLATFORMCREATE))
        return TPM_RC_NV_AUTHORIZATION;

    // Internal Data Update

    // Call implementation dependent internal routine to delete NV index
    return NvDeleteIndex(nvIndex, locator);
}

#endif  // CC_NV_UndefineSpace