// This file contains an inlined portion of the s_ccAttr array definition
// for vendor commands.
//
// IMPORTANT:  This file is included in the middle of an array initializer
// therefore it must not contain anything other than comments and exactly one TPMA_CC
// entry per vendor command.  See the private Tpm header CommandAttributeData.h for
// more info.
// (This is why the file has the .INL extension, it's not a normal header.
//
#ifndef _COMMAND_TABLE_DISPATCH_
#error This file should only be included inside CommandDispatchData.h when table dispatching is turned on.
#endif
#if (PAD_LIST || CC_Vendor_TCG_Test)
(COMMAND_DESCRIPTOR_t*)_Vendor_TCG_TestDataAddress,
#endif  // CC_Vendor_TCG_Test
