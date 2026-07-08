#ifndef _PLATFORM_VIRTUAL_FP_H_
#define _PLATFORM_VIRTUAL_FP_H_

#include <private/prototypes/NV_Read_fp.h>
#include <private/prototypes/NV_ReadPublic_fp.h>

// The ECC EK Cert and EK ICA Cert NV indexes are not populated like normal.
// Data is generated on the fly and returned when NV_Read or NV_ReadPublic is
// called for them. This function populates the given NV_VIRTUAL_INDEX structure with
// attributes for the EK cert and EKICA cert scenarios. If the NV index is not virtual,
// the function should return TPM_RC_NO_RESULT.
LIB_EXPORT TPM_RC _plat__NvVirtual_PopulateNvIndexInfo(
    TPM_HANDLE      handle,      // IN: handle for the index
    TPMS_NV_PUBLIC* publicArea,  // INOUT: The public area structure to be modified.
    TPM2B_AUTH*     authValue    // INOUT: The auth value structure to be modified.
);

// Performs NV Read call to handle EK/EKICA cert scenarios.
LIB_EXPORT TPM_RC _plat__NvVirtual_Read(
    NV_Read_In*  dataIn,  // IN: input parameter list
    NV_Read_Out* dataOut  // OUT: output parameter list
);

// Performs NV Read Public call to handle EK/EKICA cert scenarios.
LIB_EXPORT TPM_RC _plat__NvVirtual_ReadPublic(
    NV_ReadPublic_In*  dataIn,  // IN: input parameter list
    NV_ReadPublic_Out* dataOut  // OUT: output parameter list
);

// Returns a list of handles of virtual NV indices, starting from 'handle'.
// 'Handle' must be in the range of NV indices, but does not have to reference
// an existing virtual NV Index.
LIB_EXPORT TPMI_YES_NO _plat__NvVirtual_CapGetIndex(
    TPMI_DH_OBJECT handle,     // IN: start handle
    UINT32         count,      // IN: max number of returned handles
    TPML_HANDLE*   handleList  // OUT: list of handle
);

// Does this NV operation accept virtual NV handles?
// If the operation is not an NV operation, returns false.
LIB_EXPORT BOOL _plat__NvOperationAcceptsVirtualHandles(TPM_CC commandCode);

// Checks if the given handle belongs to one of the virtual indices.
// Currently only used with the ECC EK Certificate and EKICA Certificate
// indices.
LIB_EXPORT BOOL _plat__IsNvVirtualIndex(TPM_HANDLE handle);

#endif  // _PLATFORM_VIRTUAL_FP_H_
