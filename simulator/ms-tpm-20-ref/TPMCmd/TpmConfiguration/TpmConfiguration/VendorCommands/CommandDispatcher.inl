// This file contains an inlined portion of the CommandDispatcher.c
// command dispatch switch statement.
//
// IMPORTANT:  This file is included in the middle of a switch statement, and
// therefore it must not contain anything other than switch blocks
// (This is why the file has the .INL extension, it's not a normal header.
//
#if CC_Vendor_TCG_Test
case TPM_CC_Vendor_TCG_Test:
{
    Vendor_TCG_Test_In* in =
        (Vendor_TCG_Test_In*)MemoryGetInBuffer(sizeof(Vendor_TCG_Test_In));
    Vendor_TCG_Test_Out* out =
        (Vendor_TCG_Test_Out*)MemoryGetOutBuffer(sizeof(Vendor_TCG_Test_Out));
    result = TPM2B_DATA_Unmarshal(&in->inputData, paramBuffer, paramBufferSize);
    EXIT_IF_ERROR_PLUS(RC_Vendor_TCG_Test_inputData);
    if(*paramBufferSize != 0)
    {
        result = TPM_RC_SIZE;
        goto Exit;
    }
    result = TPM2_Vendor_TCG_Test(in, out);
    if(result != TPM_RC_SUCCESS)
        return result;
    rSize = sizeof(Vendor_TCG_Test_Out);
    *respParmSize += TPM2B_DATA_Marshal(&out->outputData, responseBuffer, &rSize);
    break;
}
#endif  // CC_Vendor_TCG_Test
