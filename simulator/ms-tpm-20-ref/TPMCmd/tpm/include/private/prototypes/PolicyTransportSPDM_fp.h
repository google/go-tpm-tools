#if CC_PolicyTransportSPDM  // Command must be enabled

#  ifndef _TPM_INCLUDE_PRIVATE_PROTOTYPES_POLICYTRANSPORTSPDM_FP_H_
#    define _TPM_INCLUDE_PRIVATE_PROTOTYPES_POLICYTRANSPORTSPDM_FP_H_

// Input structure definition
typedef struct
{
    TPMI_SH_POLICY policySession;
    TPM2B_NAME     reqKeyName;
    TPM2B_NAME     tpmKeyName;
} PolicyTransportSPDM_In;

// Response code modifiers
#    define RC_PolicyTransportSPDM_policySession (TPM_RC_H + TPM_RC_1)
#    define RC_PolicyTransportSPDM_reqKeyName    (TPM_RC_P + TPM_RC_1)
#    define RC_PolicyTransportSPDM_tpmKeyName    (TPM_RC_P + TPM_RC_2)

// Function prototype
TPM_RC
TPM2_PolicyTransportSPDM(PolicyTransportSPDM_In* in);

#  endif  // _TPM_INCLUDE_PRIVATE_PROTOTYPES_POLICYTRANSPORTSPDM_FP_H_
#endif    // CC_PolicyTransportSPDM
