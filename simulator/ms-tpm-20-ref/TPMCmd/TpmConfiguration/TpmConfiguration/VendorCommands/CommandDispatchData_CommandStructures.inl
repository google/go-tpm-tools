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

#if CC_Vendor_TCG_Test
#  include "TpmConfiguration/VendorCommands/prototypes/Vendor_TCG_Test_fp.h"

typedef TPM_RC(Vendor_TCG_Test_Entry)(Vendor_TCG_Test_In*  in,
                                      Vendor_TCG_Test_Out* out);

typedef const struct
{
    Vendor_TCG_Test_Entry* entry;
    UINT16                 inSize;
    UINT16                 outSize;
    UINT16                 offsetOfTypes;
    BYTE                   types[4];
} Vendor_TCG_Test_COMMAND_DESCRIPTOR_t;

Vendor_TCG_Test_COMMAND_DESCRIPTOR_t _Vendor_TCG_TestData = {
    /* entry         */ &TPM2_Vendor_TCG_Test,
    /* inSize        */ (UINT16)(sizeof(Vendor_TCG_Test_In)),
    /* outSize       */ (UINT16)(sizeof(Vendor_TCG_Test_Out)),
    /* offsetOfTypes */ offsetof(Vendor_TCG_Test_COMMAND_DESCRIPTOR_t, types),
    /* offsets       */  // No parameter offsets
                         /* types         */
    {TPM2B_DATA_P_UNMARSHAL, END_OF_LIST, TPM2B_DATA_P_MARSHAL, END_OF_LIST}};

#  define _Vendor_TCG_TestDataAddress (&_Vendor_TCG_TestData)
#else
#  define _Vendor_TCG_TestDataAddress 0
#endif  // CC_Vendor_TCG_Test
