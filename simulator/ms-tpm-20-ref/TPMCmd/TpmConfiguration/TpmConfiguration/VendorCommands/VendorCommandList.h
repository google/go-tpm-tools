// This file defines any Vendor command IDs, and must also define the
// VENDOR_COMMAND_ARRAY_COUNT which is consumed by the CoreLibrary.
// This file is included inside TpmProfile_CommandList.h and therefore
// has access to CC_YES and CC_NO for turning commands on and off.

#ifndef _TPM_PROFILE_COMMAND_LIST_H_
#  error This file should be included only within TpmProfile_CommandList.h
#endif

#define CC_Vendor_TCG_Test CC_YES

#define VENDOR_COMMAND_ARRAY_COUNT (CC_Vendor_TCG_Test)

// actually define vendor command IDs here
#if CC_Vendor_TCG_Test == YES
#  define TPM_CC_Vendor_TCG_Test (TPM_CC)(CC_VEND | 0x0000)
#else
// nothing
#endif
// and command attributes must be defined in TpmProfile_CommandList_AttributeData.inl