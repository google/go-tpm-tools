// This file contains an inlined portion of the s_ccAttr array definition
// for vendor commands.
//
// IMPORTANT:  This file is included in the middle of an array initializer
// therefore it must not contain anything other than comments and exactly one TPMA_CC
// entry per vendor command.  See the private Tpm header CommandAttributeData.h for
// more info.
// (This is why the file has the .INL extension, it's not a normal header.
//
#ifndef _COMMAND_CODE_ATTRIBUTES_
#  error This file should be included only within CommandAttributeData.h
#endif
#if (PAD_LIST || CC_Vendor_TCG_Test)
// TPM_CC_Vendor_TCG_Test
TPMA_CC_INITIALIZER(0x0000, 0, 0, 0, 0, 0, 0, 1, 0),
#endif
