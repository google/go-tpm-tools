#include "Platform.h"
#include <tpm_public/TpmAlgorithmDefines.h>
#include <tpm_public/TpmTypes.h>
#include <platform_interface/prototypes/platform_virtual_nv_fp.h>

// NV Index handles for EKICA and EK Certificates.
#define RSA_2048_EK_CERT_HANDLE (0x01c00002)
#define ECC_P256_EK_CERT_HANDLE (0x01c0000a)
#define ECC_EK_ICA_HANDLE       (0x01c00100)

LIB_EXPORT TPM_RC _plat__NvVirtual_PopulateNvIndexInfo(
    TPM_HANDLE      handle,      // IN: handle for the index
    TPMS_NV_PUBLIC* publicArea,  // INOUT: The public area structure to be modified.
    TPM2B_AUTH*     authValue    // INOUT: The auth value structure to be modified.
)
{
    NOT_REFERENCED(handle);
    NOT_REFERENCED(publicArea);
    NOT_REFERENCED(authValue);
    return TPM_RC_NO_RESULT;
}

LIB_EXPORT TPM_RC _plat__NvVirtual_Read(
    NV_Read_In*  in,  // IN: input parameter list
    NV_Read_Out* out  // OUT: output parameter list
)
{
    NOT_REFERENCED(in);
    NOT_REFERENCED(out);
    return TPM_RC_NO_RESULT;
}

LIB_EXPORT TPM_RC _plat__NvVirtual_ReadPublic(
    NV_ReadPublic_In*  in,  // IN: input parameter list
    NV_ReadPublic_Out* out  // OUT: output parameter list
)
{
    NOT_REFERENCED(in);
    NOT_REFERENCED(out);
    return TPM_RC_NO_RESULT;
}

LIB_EXPORT TPMI_YES_NO _plat__NvVirtual_CapGetIndex(
    TPMI_DH_OBJECT handle,     // IN: start handle
    UINT32         count,      // IN: max number of returned handles
    TPML_HANDLE*   handleList  // OUT: list of handle
)
{
    NOT_REFERENCED(handle);
    NOT_REFERENCED(count);
    NOT_REFERENCED(handleList);
    return NO;
}

LIB_EXPORT BOOL _plat__NvOperationAcceptsVirtualHandles(TPM_CC commandCode)
{
    NOT_REFERENCED(commandCode);
    return FALSE;
}

LIB_EXPORT BOOL _plat__IsNvVirtualIndex(TPM_HANDLE handle)
{
    NOT_REFERENCED(handle);
    // might be something like this:
    // (handle == ECC_P256_EK_CERT_HANDLE || handle == RSA_2048_EK_CERT_HANDLE
    //   || handle == ECC_EK_ICA_HANDLE);
    return FALSE;
}
