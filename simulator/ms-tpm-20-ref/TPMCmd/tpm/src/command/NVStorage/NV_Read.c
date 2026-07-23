#include "Tpm.h"
#include "NV_Read_fp.h"
#include <platform_interface/prototypes/platform_virtual_nv_fp.h>

#if CC_NV_Read  // Conditional expansion of this file

/*(See part 3 specification)
// Read of an NV index
*/
//  Return Type: TPM_RC
//      TPM_RC_NV_AUTHORIZATION         the authorization was valid but the
//                                      authorizing entity ('authHandle')
//                                      is not allowed to read from the Index
//                                      referenced by 'nvIndex'
//      TPM_RC_NV_LOCKED                the Index referenced by 'nvIndex' is
//                                      read locked
//      TPM_RC_NV_RANGE                 read range defined by 'size' and 'offset'
//                                      is outside the range of the Index referenced
//                                      by 'nvIndex'
//      TPM_RC_NV_UNINITIALIZED         the Index referenced by 'nvIndex' has
//                                      not been initialized (written)
//      TPM_RC_VALUE                    the read size is larger than the
//                                      MAX_NV_BUFFER_SIZE
TPM_RC
TPM2_NV_Read(NV_Read_In*  in,  // IN: input parameter list
             NV_Read_Out* out  // OUT: output parameter list
)
{
    // Handle special cases for EK cert and EKICA cert.
    if(_plat__IsNvVirtualIndex(in->nvIndex))
    {
        return _plat__NvVirtual_Read(in, out);
    }

    NV_REF    locator;
    NV_INDEX* nvIndex = NvGetIndexInfo(in->nvIndex, &locator);
    TPM_RC    result;

    // Input Validation
    // Common read access checks. NvReadAccessChecks() may return
    // TPM_RC_NV_AUTHORIZATION, TPM_RC_NV_LOCKED, or TPM_RC_NV_UNINITIALIZED
    result = NvReadAccessChecks(
        in->authHandle, in->nvIndex, nvIndex->publicArea.attributes);
    if(result != TPM_RC_SUCCESS)
        return result;

    // Make sure the data will fit the return buffer
    if(in->size > MAX_NV_BUFFER_SIZE)
        return TPM_RCS_VALUE + RC_NV_Read_size;

    // Verify that the offset is not too large
    if(in->offset > nvIndex->publicArea.dataSize)
        return TPM_RCS_VALUE + RC_NV_Read_offset;

    // Make sure that the selection is within the range of the Index
    if(in->size > (nvIndex->publicArea.dataSize - in->offset))
        return TPM_RC_NV_RANGE;

    // Command Output
    // Set the return size
    out->data.t.size = in->size;

    // Perform the read
    NvGetIndexData(nvIndex, locator, in->offset, in->size, out->data.t.buffer);

    return TPM_RC_SUCCESS;
}

#endif  // CC_NV_Read