
#if CC_ReadOnlyControl  // Command must be enabled

#  ifndef _TPM_INCLUDE_PRIVATE_PROTOTYPES_READONLYCONTROL_FP_H_
#    define _TPM_INCLUDE_PRIVATE_PROTOTYPES_READONLYCONTROL_FP_H_

// Input structure definition
typedef struct
{
    TPMI_RH_PLATFORM authHandle;
    TPMI_YES_NO      state;
} ReadOnlyControl_In;

// Response code modifiers
#    define ReadOnlyControl_authHandle (TPM_RC_H + TPM_RC_1)
#    define ReadOnlyControl_state      (TPM_RC_P + TPM_RC_1)

// Function prototype
TPM_RC TPM2_ReadOnlyControl(ReadOnlyControl_In* in);

#  endif  // _TPM_INCLUDE_PRIVATE_PROTOTYPES_READONLYCONTROL_FP_H_
#endif    // CC_ReadOnlyControl
