#include "Tpm.h"
#include "NV_DefineSpace2_fp.h"

#if CC_NV_DefineSpace2  // Conditional expansion of this file

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
TPM2_NV_DefineSpace2(NV_DefineSpace2_In* in  // IN: input parameter list
)
{
    TPM_RC         result;
    TPMS_NV_PUBLIC legacyPublic;

    // Input Validation

    // Validate the handle type and the (handle-type-specific) attributes.
    switch(in->publicInfo.nvPublic2.handleType)
    {
        case TPM_HT_NV_INDEX:
            break;
#  if EXTERNAL_NV
        case TPM_HT_EXTERNAL_NV:
            // The reference implementation may let you define an "external" NV
            // index, but it doesn't currently support setting any of the extended
            // bits for customizing the behavior of external NV.
            if((TPMA_NV_EXP_TO_UINT64(
                    in->publicInfo.nvPublic2.nvPublic2.externalNV.attributes)
                & 0xffffffff00000000)
               != 0)
            {
                return TPM_RCS_ATTRIBUTES + RC_NV_DefineSpace2_publicInfo;
            }
            break;
#  endif
        default:
            return TPM_RCS_HANDLE + RC_NV_DefineSpace2_publicInfo;
    }

    result = NvPublicFromNvPublic2(&in->publicInfo.nvPublic2, &legacyPublic);
    if(result != TPM_RC_SUCCESS)
    {
        return RcSafeAddToResult(result, RC_NV_DefineSpace2_publicInfo);
    }

    return NvDefineSpace(in->authHandle,
                         &in->auth,
                         &legacyPublic,
                         RC_NV_DefineSpace2_authHandle,
                         RC_NV_DefineSpace2_auth,
                         RC_NV_DefineSpace2_publicInfo);
}

#endif  // CC_NV_DefineSpace