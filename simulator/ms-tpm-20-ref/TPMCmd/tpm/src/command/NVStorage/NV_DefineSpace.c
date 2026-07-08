#include "Tpm.h"
#include "NV_DefineSpace_fp.h"

#if CC_NV_DefineSpace  // Conditional expansion of this file

/*(See part 3 specification)
// Define a NV index space
*/
//  Return Type: TPM_RC
//      TPM_RC_HIERARCHY            for authorizations using TPM_RH_PLATFORM
//                                  phEnable_NV is clear preventing access to NV
//                                  data in the platform hierarchy.
//      TPM_RC_ATTRIBUTES           attributes of the index are not consistent
//      TPM_RC_NV_DEFINED           index already exists
//      TPM_RC_NV_SPACE             insufficient space for the index
//      TPM_RC_SIZE                 'auth->size' or 'publicInfo->authPolicy.size' is
//                                  larger than the digest size of
//                                  'publicInfo->nameAlg'; or 'publicInfo->dataSize'
//                                  is not consistent with 'publicInfo->attributes'
//                                  (this includes the case when the index is
//                                   larger than a MAX_NV_BUFFER_SIZE but the
//                                   TPMA_NV_WRITEALL attribute is SET)
TPM_RC
TPM2_NV_DefineSpace(NV_DefineSpace_In* in  // IN: input parameter list
)
{
    // This command only supports TPM_HT_NV_INDEX-typed NV indices.
    if(HandleGetType(in->publicInfo.nvPublic.nvIndex) != TPM_HT_NV_INDEX)
    {
        return TPM_RCS_HANDLE + RC_NV_DefineSpace_publicInfo;
    }

    return NvDefineSpace(in->authHandle,
                         &in->auth,
                         &in->publicInfo.nvPublic,
                         RC_NV_DefineSpace_authHandle,
                         RC_NV_DefineSpace_auth,
                         RC_NV_DefineSpace_publicInfo);
}

#endif  // CC_NV_DefineSpace