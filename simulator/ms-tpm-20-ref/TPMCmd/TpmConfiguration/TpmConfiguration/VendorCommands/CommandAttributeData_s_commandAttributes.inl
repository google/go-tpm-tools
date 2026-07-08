// This file contains an inlined portion of the s_commandAttributes array
// definition for vendor commands.
//
// IMPORTANT:  This file is included in the middle of an array initializer
// therefore it must not contain anything other than comments and exactly one
// COMMAND_ATTRIBUTES entry per vendor command.  See the private Tpm header
// CommandAttributeData.h for more info. (This is why the file has the .INL
// extension, it's not a normal header.
//
#ifndef _COMMAND_CODE_ATTRIBUTES_
#  error This file should be included only within CommandAttributeData.h
#endif
#if (PAD_LIST || CC_Vendor_TCG_Test)
(COMMAND_ATTRIBUTES)(CC_Vendor_TCG_Test*  // 0x0000
                     (DECRYPT_2 + ENCRYPT_2)),
#endif
