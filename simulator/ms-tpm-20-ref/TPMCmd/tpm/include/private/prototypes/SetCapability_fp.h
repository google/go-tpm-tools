
#if CC_SetCapability  // Command must be enabled

#  ifndef _TPM_INCLUDE_PRIVATE_PROTOTYPES_SETCAPABILITY_FP_H_
#    define _TPM_INCLUDE_PRIVATE_PROTOTYPES_SETCAPABILITY_FP_H_

// Input structure definition
typedef struct
{
    TPMI_RH_HIERARCHY         authHandle;
    TPM2B_SET_CAPABILITY_DATA setCapabilityData;
} SetCapability_In;

// Response code modifiers
#    define SetCapability_authHandle        (TPM_RC_H + TPM_RC_1)
#    define SetCapability_setCapabilityData (TPM_RC_P + TPM_RC_1)

// Function prototype
TPM_RC TPM2_SetCapability(SetCapability_In* in);

#  endif  // _TPM_INCLUDE_PRIVATE_PROTOTYPES_SETCAPABILITY_FP_H_
#endif    // CC_SetCapability
