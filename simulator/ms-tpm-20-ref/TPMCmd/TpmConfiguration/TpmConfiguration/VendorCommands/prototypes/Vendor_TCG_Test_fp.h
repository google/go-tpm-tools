
#if CC_Vendor_TCG_Test  // Command must be enabled

#  ifndef _TPM_INCLUDE_PRIVATE_PROTOTYPES_VENDOR_TCG_TEST_FP_H_
#    define _TPM_INCLUDE_PRIVATE_PROTOTYPES_VENDOR_TCG_TEST_FP_H_

// Input structure definition
typedef struct
{
    TPM2B_DATA inputData;
} Vendor_TCG_Test_In;

// Output structure definition
typedef struct
{
    TPM2B_DATA outputData;
} Vendor_TCG_Test_Out;

// Response code modifiers
#    define RC_Vendor_TCG_Test_inputData (TPM_RC_P + TPM_RC_1)

// Function prototype
TPM_RC
TPM2_Vendor_TCG_Test(Vendor_TCG_Test_In* in, Vendor_TCG_Test_Out* out);

#  endif  // _TPM_INCLUDE_PRIVATE_PROTOTYPES_VENDOR_TCG_TEST_FP_H_
#endif    // CC_Vendor_TCG_Test
