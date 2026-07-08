#include "Tpm.h"
#include "NV_ChangeAuth_fp.h"

#if CC_NV_ChangeAuth  // Conditional expansion of this file

/*(See part 3 specification)
// change authorization value of a NV index
*/
//  Return Type: TPM_RC
//      TPM_RC_SIZE                     'newAuth' size is larger than the digest
//                                      size of the Name algorithm for the Index
//                                      referenced by 'nvIndex'
TPM_RC
TPM2_NV_ChangeAuth(NV_ChangeAuth_In* in  // IN: input parameter list
)
{
    NV_REF    locator;
    NV_INDEX* nvIndex = NvGetIndexInfo(in->nvIndex, &locator);

    // Input Validation

    // Remove trailing zeros and make sure that the result is not larger than the
    // digest of the nameAlg.
    if(MemoryRemoveTrailingZeros(&in->newAuth)
       > CryptHashGetDigestSize(nvIndex->publicArea.nameAlg))
        return TPM_RCS_SIZE + RC_NV_ChangeAuth_newAuth;

    // Internal Data Update
    // Change authValue
    return NvWriteIndexAuth(locator, &in->newAuth);
}

#endif  // CC_NV_ChangeAuth