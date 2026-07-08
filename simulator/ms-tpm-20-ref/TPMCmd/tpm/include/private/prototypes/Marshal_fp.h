
#ifndef _MARSHAL_FP_H_
#define _MARSHAL_FP_H_

#include <tpm_public/BaseTypes.h>

// Table "Definition of Base Types" (Part 2: Structures)
//   UINT8 definition
TPM_RC
UINT8_Unmarshal(UINT8* target, BYTE** buffer, INT32* size);
UINT16
UINT8_Marshal(UINT8* source, BYTE** buffer, INT32* size);

//   BYTE definition
TPM_INLINE TPM_RC BYTE_Unmarshal(BYTE* target, BYTE** buffer, INT32* size)
{
    return UINT8_Unmarshal((UINT8*)(target), (buffer), (size));
}
TPM_INLINE UINT16 BYTE_Marshal(BYTE* source, BYTE** buffer, INT32* size)
{
    return UINT8_Marshal((UINT8*)(source), (buffer), (size));
}

//   INT8 definition
TPM_INLINE TPM_RC INT8_Unmarshal(INT8* target, BYTE** buffer, INT32* size)
{
    return UINT8_Unmarshal((UINT8*)(target), (buffer), (size));
}
TPM_INLINE UINT16 INT8_Marshal(INT8* source, BYTE** buffer, INT32* size)
{
    return UINT8_Marshal((UINT8*)(source), (buffer), (size));
}

//   UINT16 definition
TPM_RC
UINT16_Unmarshal(UINT16* target, BYTE** buffer, INT32* size);
UINT16
UINT16_Marshal(UINT16* source, BYTE** buffer, INT32* size);

//   INT16 definition
TPM_INLINE TPM_RC INT16_Unmarshal(INT16* target, BYTE** buffer, INT32* size)
{
    return UINT16_Unmarshal((UINT16*)(target), (buffer), (size));
}
TPM_INLINE UINT16 INT16_Marshal(INT16* source, BYTE** buffer, INT32* size)
{
    return UINT16_Marshal((UINT16*)(source), (buffer), (size));
}

//   UINT32 definition
TPM_RC
UINT32_Unmarshal(UINT32* target, BYTE** buffer, INT32* size);
UINT16
UINT32_Marshal(UINT32* source, BYTE** buffer, INT32* size);

//   INT32 definition
TPM_INLINE TPM_RC INT32_Unmarshal(INT32* target, BYTE** buffer, INT32* size)
{
    return UINT32_Unmarshal((UINT32*)(target), (buffer), (size));
}
TPM_INLINE UINT16 INT32_Marshal(INT32* source, BYTE** buffer, INT32* size)
{
    return UINT32_Marshal((UINT32*)(source), (buffer), (size));
}

//   UINT64 definition
TPM_RC
UINT64_Unmarshal(UINT64* target, BYTE** buffer, INT32* size);
UINT16
UINT64_Marshal(UINT64* source, BYTE** buffer, INT32* size);

//   INT64 definition
TPM_INLINE TPM_RC INT64_Unmarshal(INT64* target, BYTE** buffer, INT32* size)
{
    return UINT64_Unmarshal((UINT64*)(target), (buffer), (size));
}
TPM_INLINE UINT16 INT64_Marshal(INT64* source, BYTE** buffer, INT32* size)
{
    return UINT64_Marshal((UINT64*)(source), (buffer), (size));
}

// Table "Definition of Types for Documentation Clarity" (Part 2: Structures)
TPM_INLINE TPM_RC TPM_ALGORITHM_ID_Unmarshal(
    TPM_ALGORITHM_ID* target, BYTE** buffer, INT32* size)
{
    return UINT32_Unmarshal((UINT32*)(target), (buffer), (size));
}
TPM_INLINE UINT16 TPM_ALGORITHM_ID_Marshal(
    TPM_ALGORITHM_ID* source, BYTE** buffer, INT32* size)
{
    return UINT32_Marshal((UINT32*)(source), (buffer), (size));
}
TPM_INLINE TPM_RC TPM_AUTHORIZATION_SIZE_Unmarshal(
    TPM_AUTHORIZATION_SIZE* target, BYTE** buffer, INT32* size)
{
    return UINT32_Unmarshal((UINT32*)(target), (buffer), (size));
}
TPM_INLINE UINT16 TPM_AUTHORIZATION_SIZE_Marshal(
    TPM_AUTHORIZATION_SIZE* source, BYTE** buffer, INT32* size)
{
    return UINT32_Marshal((UINT32*)(source), (buffer), (size));
}
TPM_INLINE TPM_RC TPM_KEY_BITS_Unmarshal(
    TPM_KEY_BITS* target, BYTE** buffer, INT32* size)
{
    return UINT16_Unmarshal((UINT16*)(target), (buffer), (size));
}
TPM_INLINE UINT16 TPM_KEY_BITS_Marshal(
    TPM_KEY_BITS* source, BYTE** buffer, INT32* size)
{
    return UINT16_Marshal((UINT16*)(source), (buffer), (size));
}
TPM_INLINE TPM_RC TPM_KEY_SIZE_Unmarshal(
    TPM_KEY_SIZE* target, BYTE** buffer, INT32* size)
{
    return UINT16_Unmarshal((UINT16*)(target), (buffer), (size));
}
TPM_INLINE UINT16 TPM_KEY_SIZE_Marshal(
    TPM_KEY_SIZE* source, BYTE** buffer, INT32* size)
{
    return UINT16_Marshal((UINT16*)(source), (buffer), (size));
}
TPM_INLINE TPM_RC TPM_MODIFIER_INDICATOR_Unmarshal(
    TPM_MODIFIER_INDICATOR* target, BYTE** buffer, INT32* size)
{
    return UINT32_Unmarshal((UINT32*)(target), (buffer), (size));
}
TPM_INLINE UINT16 TPM_MODIFIER_INDICATOR_Marshal(
    TPM_MODIFIER_INDICATOR* source, BYTE** buffer, INT32* size)
{
    return UINT32_Marshal((UINT32*)(source), (buffer), (size));
}
TPM_INLINE TPM_RC TPM_PARAMETER_SIZE_Unmarshal(
    TPM_PARAMETER_SIZE* target, BYTE** buffer, INT32* size)
{
    return UINT32_Unmarshal((UINT32*)(target), (buffer), (size));
}
TPM_INLINE UINT16 TPM_PARAMETER_SIZE_Marshal(
    TPM_PARAMETER_SIZE* source, BYTE** buffer, INT32* size)
{
    return UINT32_Marshal((UINT32*)(source), (buffer), (size));
}

// Table "Definition of TPM_CONSTANTS32 Constants" (Part 2: Structures)
TPM_INLINE UINT16 TPM_CONSTANTS32_Marshal(
    TPM_CONSTANTS32* source, BYTE** buffer, INT32* size)
{
    return UINT32_Marshal((UINT32*)(source), (buffer), (size));
}

// Table "Definition of TPM_ALG_ID Constants" (Part 2: Structures)
TPM_INLINE TPM_RC TPM_ALG_ID_Unmarshal(TPM_ALG_ID* target, BYTE** buffer, INT32* size)
{
    return UINT16_Unmarshal((UINT16*)(target), (buffer), (size));
}
TPM_INLINE UINT16 TPM_ALG_ID_Marshal(TPM_ALG_ID* source, BYTE** buffer, INT32* size)
{
    return UINT16_Marshal((UINT16*)(source), (buffer), (size));
}

// Table "Definition of TPM_ECC_CURVE Constants" (Part 2: Structures)
TPM_RC
TPM_ECC_CURVE_Unmarshal(TPM_ECC_CURVE* target, BYTE** buffer, INT32* size);
TPM_INLINE UINT16 TPM_ECC_CURVE_Marshal(
    TPM_ECC_CURVE* source, BYTE** buffer, INT32* size)
{
    return UINT16_Marshal((UINT16*)(source), (buffer), (size));
}

// Table "Definition of TPM_CC Constants" (Part 2: Structures)
TPM_INLINE TPM_RC TPM_CC_Unmarshal(TPM_CC* target, BYTE** buffer, INT32* size)
{
    return UINT32_Unmarshal((UINT32*)(target), (buffer), (size));
}
TPM_INLINE UINT16 TPM_CC_Marshal(TPM_CC* source, BYTE** buffer, INT32* size)
{
    return UINT32_Marshal((UINT32*)(source), (buffer), (size));
}

// Table "Definition of TPM_RC Constants" (Part 2: Structures)
TPM_INLINE UINT16 TPM_RC_Marshal(TPM_RC* source, BYTE** buffer, INT32* size)
{
    return UINT32_Marshal((UINT32*)(source), (buffer), (size));
}

// Table "Definition of TPM_CLOCK_ADJUST Constants" (Part 2: Structures)
TPM_RC
TPM_CLOCK_ADJUST_Unmarshal(TPM_CLOCK_ADJUST* target, BYTE** buffer, INT32* size);

// Table "Definition of TPM_EO Constants" (Part 2: Structures)
TPM_RC
TPM_EO_Unmarshal(TPM_EO* target, BYTE** buffer, INT32* size);
TPM_INLINE UINT16 TPM_EO_Marshal(TPM_EO* source, BYTE** buffer, INT32* size)
{
    return UINT16_Marshal((UINT16*)(source), (buffer), (size));
}

// Table "Definition of TPM_ST Constants" (Part 2: Structures)
TPM_INLINE TPM_RC TPM_ST_Unmarshal(TPM_ST* target, BYTE** buffer, INT32* size)
{
    return UINT16_Unmarshal((UINT16*)(target), (buffer), (size));
}
TPM_INLINE UINT16 TPM_ST_Marshal(TPM_ST* source, BYTE** buffer, INT32* size)
{
    return UINT16_Marshal((UINT16*)(source), (buffer), (size));
}

// Table "Definition of TPM_SU Constants" (Part 2: Structures)
TPM_RC
TPM_SU_Unmarshal(TPM_SU* target, BYTE** buffer, INT32* size);

// Table "Definition of TPM_SE Constants" (Part 2: Structures)
TPM_RC
TPM_SE_Unmarshal(TPM_SE* target, BYTE** buffer, INT32* size);

// Table "Definition of TPM_CAP Constants" (Part 2: Structures)
TPM_RC
TPM_CAP_Unmarshal(TPM_CAP* target, BYTE** buffer, INT32* size);
TPM_INLINE UINT16 TPM_CAP_Marshal(TPM_CAP* source, BYTE** buffer, INT32* size)
{
    return UINT32_Marshal((UINT32*)(source), (buffer), (size));
}

// Table "Definition of TPM_PT Constants" (Part 2: Structures)
TPM_INLINE TPM_RC TPM_PT_Unmarshal(TPM_PT* target, BYTE** buffer, INT32* size)
{
    return UINT32_Unmarshal((UINT32*)(target), (buffer), (size));
}
TPM_INLINE UINT16 TPM_PT_Marshal(TPM_PT* source, BYTE** buffer, INT32* size)
{
    return UINT32_Marshal((UINT32*)(source), (buffer), (size));
}

// Table "Definition of TPM_PT_PCR Constants" (Part 2: Structures)
TPM_INLINE TPM_RC TPM_PT_PCR_Unmarshal(TPM_PT_PCR* target, BYTE** buffer, INT32* size)
{
    return UINT32_Unmarshal((UINT32*)(target), (buffer), (size));
}
TPM_INLINE UINT16 TPM_PT_PCR_Marshal(TPM_PT_PCR* source, BYTE** buffer, INT32* size)
{
    return UINT32_Marshal((UINT32*)(source), (buffer), (size));
}

// Table "Definition of TPM_PS Constants" (Part 2: Structures)
TPM_INLINE UINT16 TPM_PS_Marshal(TPM_PS* source, BYTE** buffer, INT32* size)
{
    return UINT32_Marshal((UINT32*)(source), (buffer), (size));
}

// Table "Definition of Types for Handles" (Part 2: Structures)
TPM_INLINE TPM_RC TPM_HANDLE_Unmarshal(TPM_HANDLE* target, BYTE** buffer, INT32* size)
{
    return UINT32_Unmarshal((UINT32*)(target), (buffer), (size));
}
TPM_INLINE UINT16 TPM_HANDLE_Marshal(TPM_HANDLE* source, BYTE** buffer, INT32* size)
{
    return UINT32_Marshal((UINT32*)(source), (buffer), (size));
}

// Table "Definition of TPM_HT Constants" (Part 2: Structures)
TPM_INLINE TPM_RC TPM_HT_Unmarshal(TPM_HT* target, BYTE** buffer, INT32* size)
{
    return UINT8_Unmarshal((UINT8*)(target), (buffer), (size));
}
TPM_INLINE UINT16 TPM_HT_Marshal(TPM_HT* source, BYTE** buffer, INT32* size)
{
    return UINT8_Marshal((UINT8*)(source), (buffer), (size));
}

// Table "Definition of TPM_RH Constants" (Part 2: Structures)
TPM_INLINE TPM_RC TPM_RH_Unmarshal(TPM_RH* target, BYTE** buffer, INT32* size)
{
    return TPM_HANDLE_Unmarshal((TPM_HANDLE*)(target), (buffer), (size));
}
TPM_INLINE UINT16 TPM_RH_Marshal(TPM_RH* source, BYTE** buffer, INT32* size)
{
    return TPM_HANDLE_Marshal((TPM_HANDLE*)(source), (buffer), (size));
}

// Table "Definition of TPM_HC Constants" (Part 2: Structures)
TPM_INLINE TPM_RC TPM_HC_Unmarshal(TPM_HC* target, BYTE** buffer, INT32* size)
{
    return TPM_HANDLE_Unmarshal((TPM_HANDLE*)(target), (buffer), (size));
}
TPM_INLINE UINT16 TPM_HC_Marshal(TPM_HC* source, BYTE** buffer, INT32* size)
{
    return TPM_HANDLE_Marshal((TPM_HANDLE*)(source), (buffer), (size));
}

// Table "Definition of TPMA_ALGORITHM Bits" (Part 2: Structures)
TPM_RC
TPMA_ALGORITHM_Unmarshal(TPMA_ALGORITHM* target, BYTE** buffer, INT32* size);
TPM_INLINE UINT16 TPMA_ALGORITHM_Marshal(
    TPMA_ALGORITHM* source, BYTE** buffer, INT32* size)
{
    return UINT32_Marshal((UINT32*)(source), (buffer), (size));
}

// Table "Definition of TPMA_OBJECT Bits" (Part 2: Structures)
TPM_RC
TPMA_OBJECT_Unmarshal(TPMA_OBJECT* target, BYTE** buffer, INT32* size);
TPM_INLINE UINT16 TPMA_OBJECT_Marshal(TPMA_OBJECT* source, BYTE** buffer, INT32* size)
{
    return UINT32_Marshal((UINT32*)(source), (buffer), (size));
}

// Table "Definition of TPMA_SESSION Bits" (Part 2: Structures)
TPM_RC
TPMA_SESSION_Unmarshal(TPMA_SESSION* target, BYTE** buffer, INT32* size);
TPM_INLINE UINT16 TPMA_SESSION_Marshal(
    TPMA_SESSION* source, BYTE** buffer, INT32* size)
{
    return UINT8_Marshal((UINT8*)(source), (buffer), (size));
}

// Table "Definition of TPMA_LOCALITY Bits" (Part 2: Structures)
TPM_INLINE TPM_RC TPMA_LOCALITY_Unmarshal(
    TPMA_LOCALITY* target, BYTE** buffer, INT32* size)
{
    return UINT8_Unmarshal((UINT8*)(target), (buffer), (size));
}
TPM_INLINE UINT16 TPMA_LOCALITY_Marshal(
    TPMA_LOCALITY* source, BYTE** buffer, INT32* size)
{
    return UINT8_Marshal((UINT8*)(source), (buffer), (size));
}

// Table "Definition of TPMA_PERMANENT Bits" (Part 2: Structures)
TPM_INLINE UINT16 TPMA_PERMANENT_Marshal(
    TPMA_PERMANENT* source, BYTE** buffer, INT32* size)
{
    return UINT32_Marshal((UINT32*)(source), (buffer), (size));
}

// Table "Definition of TPMA_STARTUP_CLEAR Bits" (Part 2: Structures)
TPM_INLINE UINT16 TPMA_STARTUP_CLEAR_Marshal(
    TPMA_STARTUP_CLEAR* source, BYTE** buffer, INT32* size)
{
    return UINT32_Marshal((UINT32*)(source), (buffer), (size));
}

// Table "Definition of TPMA_MEMORY Bits" (Part 2: Structures)
TPM_INLINE UINT16 TPMA_MEMORY_Marshal(TPMA_MEMORY* source, BYTE** buffer, INT32* size)
{
    return UINT32_Marshal((UINT32*)(source), (buffer), (size));
}

// Table "Definition of TPMA_CC Bits" (Part 2: Structures)
TPM_INLINE UINT16 TPMA_CC_Marshal(TPMA_CC* source, BYTE** buffer, INT32* size)
{
    return UINT32_Marshal((UINT32*)(source), (buffer), (size));
}

// Table "Definition of TPMA_MODES Bits" (Part 2: Structures)
TPM_INLINE UINT16 TPMA_MODES_Marshal(TPMA_MODES* source, BYTE** buffer, INT32* size)
{
    return UINT32_Marshal((UINT32*)(source), (buffer), (size));
}

// Table "Definition of TPMA_ACT Bits" (Part 2: Structures)
TPM_RC
TPMA_ACT_Unmarshal(TPMA_ACT* target, BYTE** buffer, INT32* size);
TPM_INLINE UINT16 TPMA_ACT_Marshal(TPMA_ACT* source, BYTE** buffer, INT32* size)
{
    return UINT32_Marshal((UINT32*)(source), (buffer), (size));
}

// Table "Definition of TPMI_YES_NO Type" (Part 2: Structures)
TPM_RC
TPMI_YES_NO_Unmarshal(TPMI_YES_NO* target, BYTE** buffer, INT32* size);
TPM_INLINE UINT16 TPMI_YES_NO_Marshal(TPMI_YES_NO* source, BYTE** buffer, INT32* size)
{
    return BYTE_Marshal((BYTE*)(source), (buffer), (size));
}

// Table "Definition of TPMI_DH_OBJECT Type" (Part 2: Structures)
TPM_RC
TPMI_DH_OBJECT_Unmarshal(
    TPMI_DH_OBJECT* target, BYTE** buffer, INT32* size, BOOL flag);
TPM_INLINE UINT16 TPMI_DH_OBJECT_Marshal(
    TPMI_DH_OBJECT* source, BYTE** buffer, INT32* size)
{
    return TPM_HANDLE_Marshal((TPM_HANDLE*)(source), (buffer), (size));
}

// Table "Definition of TPMI_DH_PARENT Type" (Part 2: Structures)
TPM_RC
TPMI_DH_PARENT_Unmarshal(TPMI_DH_PARENT* target, BYTE** buffer, INT32* size);
TPM_INLINE UINT16 TPMI_DH_PARENT_Marshal(
    TPMI_DH_PARENT* source, BYTE** buffer, INT32* size)
{
    return TPM_HANDLE_Marshal((TPM_HANDLE*)(source), (buffer), (size));
}

// Table "Definition of TPMI_DH_PERSISTENT Type" (Part 2: Structures)
TPM_RC
TPMI_DH_PERSISTENT_Unmarshal(TPMI_DH_PERSISTENT* target, BYTE** buffer, INT32* size);
TPM_INLINE UINT16 TPMI_DH_PERSISTENT_Marshal(
    TPMI_DH_PERSISTENT* source, BYTE** buffer, INT32* size)
{
    return TPM_HANDLE_Marshal((TPM_HANDLE*)(source), (buffer), (size));
}

// Table "Definition of TPMI_DH_ENTITY Type" (Part 2: Structures)
TPM_RC
TPMI_DH_ENTITY_Unmarshal(
    TPMI_DH_ENTITY* target, BYTE** buffer, INT32* size, BOOL flag);

// Table "Definition of TPMI_DH_PCR Type" (Part 2: Structures)
TPM_RC
TPMI_DH_PCR_Unmarshal(TPMI_DH_PCR* target, BYTE** buffer, INT32* size, BOOL flag);

// Table "Definition of TPMI_SH_AUTH_SESSION Type" (Part 2: Structures)
TPM_RC
TPMI_SH_AUTH_SESSION_Unmarshal(
    TPMI_SH_AUTH_SESSION* target, BYTE** buffer, INT32* size, BOOL flag);
TPM_INLINE UINT16 TPMI_SH_AUTH_SESSION_Marshal(
    TPMI_SH_AUTH_SESSION* source, BYTE** buffer, INT32* size)
{
    return TPM_HANDLE_Marshal((TPM_HANDLE*)(source), (buffer), (size));
}

// Table "Definition of TPMI_SH_HMAC Type" (Part 2: Structures)
TPM_RC
TPMI_SH_HMAC_Unmarshal(TPMI_SH_HMAC* target, BYTE** buffer, INT32* size);
TPM_INLINE UINT16 TPMI_SH_HMAC_Marshal(
    TPMI_SH_HMAC* source, BYTE** buffer, INT32* size)
{
    return TPM_HANDLE_Marshal((TPM_HANDLE*)(source), (buffer), (size));
}

// Table "Definition of TPMI_SH_POLICY Type" (Part 2: Structures)
TPM_RC
TPMI_SH_POLICY_Unmarshal(TPMI_SH_POLICY* target, BYTE** buffer, INT32* size);
TPM_INLINE UINT16 TPMI_SH_POLICY_Marshal(
    TPMI_SH_POLICY* source, BYTE** buffer, INT32* size)
{
    return TPM_HANDLE_Marshal((TPM_HANDLE*)(source), (buffer), (size));
}

// Table "Definition of TPMI_DH_CONTEXT Type" (Part 2: Structures)
TPM_RC
TPMI_DH_CONTEXT_Unmarshal(TPMI_DH_CONTEXT* target, BYTE** buffer, INT32* size);
TPM_INLINE UINT16 TPMI_DH_CONTEXT_Marshal(
    TPMI_DH_CONTEXT* source, BYTE** buffer, INT32* size)
{
    return TPM_HANDLE_Marshal((TPM_HANDLE*)(source), (buffer), (size));
}

// Table "Definition of TPMI_DH_SAVED Type" (Part 2: Structures)
TPM_RC
TPMI_DH_SAVED_Unmarshal(TPMI_DH_SAVED* target, BYTE** buffer, INT32* size);
TPM_INLINE UINT16 TPMI_DH_SAVED_Marshal(
    TPMI_DH_SAVED* source, BYTE** buffer, INT32* size)
{
    return TPM_HANDLE_Marshal((TPM_HANDLE*)(source), (buffer), (size));
}

// Table "Definition of TPMI_RH_HIERARCHY Type" (Part 2: Structures)
TPM_RC
TPMI_RH_HIERARCHY_Unmarshal(TPMI_RH_HIERARCHY* target, BYTE** buffer, INT32* size);
TPM_INLINE UINT16 TPMI_RH_HIERARCHY_Marshal(
    TPMI_RH_HIERARCHY* source, BYTE** buffer, INT32* size)
{
    return TPM_HANDLE_Marshal((TPM_HANDLE*)(source), (buffer), (size));
}

// Table "Definition of TPMI_RH_ENABLES Type" (Part 2: Structures)
TPM_RC
TPMI_RH_ENABLES_Unmarshal(
    TPMI_RH_ENABLES* target, BYTE** buffer, INT32* size, BOOL flag);
TPM_INLINE UINT16 TPMI_RH_ENABLES_Marshal(
    TPMI_RH_ENABLES* source, BYTE** buffer, INT32* size)
{
    return TPM_HANDLE_Marshal((TPM_HANDLE*)(source), (buffer), (size));
}

// Table "Definition of TPMI_RH_HIERARCHY_AUTH Type" (Part 2: Structures)
TPM_RC
TPMI_RH_HIERARCHY_AUTH_Unmarshal(
    TPMI_RH_HIERARCHY_AUTH* target, BYTE** buffer, INT32* size);

// Table "Definition of TPMI_RH_HIERARCHY_POLICY Type" (Part 2: Structures)
TPM_RC
TPMI_RH_HIERARCHY_POLICY_Unmarshal(
    TPMI_RH_HIERARCHY_POLICY* target, BYTE** buffer, INT32* size);

// Table "Definition of TPMI_RH_BASE_HIERARCHY Type" (Part 2: Structures)
TPM_RC
TPMI_RH_BASE_HIERARCHY_Unmarshal(
    TPMI_RH_BASE_HIERARCHY* target, BYTE** buffer, INT32* size);
TPM_INLINE UINT16 TPMI_RH_BASE_HIERARCHY_Marshal(
    TPMI_RH_BASE_HIERARCHY* source, BYTE** buffer, INT32* size)
{
    return TPM_HANDLE_Marshal((TPM_HANDLE*)(source), (buffer), (size));
}

// Table "Definition of TPMI_RH_PLATFORM Type" (Part 2: Structures)
TPM_RC
TPMI_RH_PLATFORM_Unmarshal(TPMI_RH_PLATFORM* target, BYTE** buffer, INT32* size);

// Table "Definition of TPMI_RH_OWNER Type" (Part 2: Structures)
TPM_RC
TPMI_RH_OWNER_Unmarshal(TPMI_RH_OWNER* target, BYTE** buffer, INT32* size, BOOL flag);

// Table "Definition of TPMI_RH_ENDORSEMENT Type" (Part 2: Structures)
TPM_RC
TPMI_RH_ENDORSEMENT_Unmarshal(
    TPMI_RH_ENDORSEMENT* target, BYTE** buffer, INT32* size, BOOL flag);

// Table "Definition of TPMI_RH_PROVISION Type" (Part 2: Structures)
TPM_RC
TPMI_RH_PROVISION_Unmarshal(TPMI_RH_PROVISION* target, BYTE** buffer, INT32* size);

// Table "Definition of TPMI_RH_CLEAR Type" (Part 2: Structures)
TPM_RC
TPMI_RH_CLEAR_Unmarshal(TPMI_RH_CLEAR* target, BYTE** buffer, INT32* size);

// Table "Definition of TPMI_RH_NV_AUTH Type" (Part 2: Structures)
TPM_RC
TPMI_RH_NV_AUTH_Unmarshal(TPMI_RH_NV_AUTH* target, BYTE** buffer, INT32* size);

// Table "Definition of TPMI_RH_LOCKOUT Type" (Part 2: Structures)
TPM_RC
TPMI_RH_LOCKOUT_Unmarshal(TPMI_RH_LOCKOUT* target, BYTE** buffer, INT32* size);

// Table "Definition of TPMI_RH_NV_INDEX Type" (Part 2: Structures)
TPM_RC
TPMI_RH_NV_INDEX_Unmarshal(TPMI_RH_NV_INDEX* target, BYTE** buffer, INT32* size);
TPM_INLINE UINT16 TPMI_RH_NV_INDEX_Marshal(
    TPMI_RH_NV_INDEX* source, BYTE** buffer, INT32* size)
{
    return TPM_HANDLE_Marshal((TPM_HANDLE*)(source), (buffer), (size));
}

// Table "Definition of TPMI_RH_NV_DEFINED_INDEX Type" (Part 2: Structures)
TPM_RC
TPMI_RH_NV_DEFINED_INDEX_Unmarshal(
    TPMI_RH_NV_DEFINED_INDEX* target, BYTE** buffer, INT32* size);

// Table "Definition of TPMI_RH_NV_LEGACY_INDEX Type" (Part 2: Structures)
TPM_RC
TPMI_RH_NV_LEGACY_INDEX_Unmarshal(
    TPMI_RH_NV_LEGACY_INDEX* target, BYTE** buffer, INT32* size);
TPM_INLINE UINT16 TPMI_RH_NV_LEGACY_INDEX_Marshal(
    TPMI_RH_NV_LEGACY_INDEX* source, BYTE** buffer, INT32* size)
{
    return TPM_HANDLE_Marshal((TPM_HANDLE*)(source), (buffer), (size));
}

// Table "Definition of TPMI_RH_NV_EXP_INDEX Type" (Part 2: Structures)
TPM_RC
TPMI_RH_NV_EXP_INDEX_Unmarshal(
    TPMI_RH_NV_EXP_INDEX* target, BYTE** buffer, INT32* size);
TPM_INLINE UINT16 TPMI_RH_NV_EXP_INDEX_Marshal(
    TPMI_RH_NV_EXP_INDEX* source, BYTE** buffer, INT32* size)
{
    return TPM_HANDLE_Marshal((TPM_HANDLE*)(source), (buffer), (size));
}

// Table "Definition of TPMI_RH_AC Type" (Part 2: Structures)
TPM_RC
TPMI_RH_AC_Unmarshal(TPMI_RH_AC* target, BYTE** buffer, INT32* size);

// Table "Definition of TPMI_RH_ACT Type" (Part 2: Structures)
TPM_RC
TPMI_RH_ACT_Unmarshal(TPMI_RH_ACT* target, BYTE** buffer, INT32* size);
TPM_INLINE UINT16 TPMI_RH_ACT_Marshal(TPMI_RH_ACT* source, BYTE** buffer, INT32* size)
{
    return TPM_HANDLE_Marshal((TPM_HANDLE*)(source), (buffer), (size));
}

// Table "Definition of TPMI_ALG_HASH Type" (Part 2: Structures)
TPM_RC
TPMI_ALG_HASH_Unmarshal(TPMI_ALG_HASH* target, BYTE** buffer, INT32* size, BOOL flag);
TPM_INLINE UINT16 TPMI_ALG_HASH_Marshal(
    TPMI_ALG_HASH* source, BYTE** buffer, INT32* size)
{
    return TPM_ALG_ID_Marshal((TPM_ALG_ID*)(source), (buffer), (size));
}

// Table "Definition of TPMI_ALG_ASYM Type" (Part 2: Structures)
TPM_RC
TPMI_ALG_ASYM_Unmarshal(TPMI_ALG_ASYM* target, BYTE** buffer, INT32* size, BOOL flag);
TPM_INLINE UINT16 TPMI_ALG_ASYM_Marshal(
    TPMI_ALG_ASYM* source, BYTE** buffer, INT32* size)
{
    return TPM_ALG_ID_Marshal((TPM_ALG_ID*)(source), (buffer), (size));
}

// Table "Definition of TPMI_ALG_SYM Type" (Part 2: Structures)
TPM_RC
TPMI_ALG_SYM_Unmarshal(TPMI_ALG_SYM* target, BYTE** buffer, INT32* size, BOOL flag);
TPM_INLINE UINT16 TPMI_ALG_SYM_Marshal(
    TPMI_ALG_SYM* source, BYTE** buffer, INT32* size)
{
    return TPM_ALG_ID_Marshal((TPM_ALG_ID*)(source), (buffer), (size));
}

// Table "Definition of TPMI_ALG_SYM_OBJECT Type" (Part 2: Structures)
TPM_RC
TPMI_ALG_SYM_OBJECT_Unmarshal(
    TPMI_ALG_SYM_OBJECT* target, BYTE** buffer, INT32* size, BOOL flag);
TPM_INLINE UINT16 TPMI_ALG_SYM_OBJECT_Marshal(
    TPMI_ALG_SYM_OBJECT* source, BYTE** buffer, INT32* size)
{
    return TPM_ALG_ID_Marshal((TPM_ALG_ID*)(source), (buffer), (size));
}

// Table "Definition of TPMI_ALG_SYM_MODE Type" (Part 2: Structures)
TPM_RC
TPMI_ALG_SYM_MODE_Unmarshal(
    TPMI_ALG_SYM_MODE* target, BYTE** buffer, INT32* size, BOOL flag);
TPM_INLINE UINT16 TPMI_ALG_SYM_MODE_Marshal(
    TPMI_ALG_SYM_MODE* source, BYTE** buffer, INT32* size)
{
    return TPM_ALG_ID_Marshal((TPM_ALG_ID*)(source), (buffer), (size));
}

// Table "Definition of TPMI_ALG_KDF Type" (Part 2: Structures)
TPM_RC
TPMI_ALG_KDF_Unmarshal(TPMI_ALG_KDF* target, BYTE** buffer, INT32* size, BOOL flag);
TPM_INLINE UINT16 TPMI_ALG_KDF_Marshal(
    TPMI_ALG_KDF* source, BYTE** buffer, INT32* size)
{
    return TPM_ALG_ID_Marshal((TPM_ALG_ID*)(source), (buffer), (size));
}

// Table "Definition of TPMI_ALG_SIG_SCHEME Type" (Part 2: Structures)
TPM_RC
TPMI_ALG_SIG_SCHEME_Unmarshal(
    TPMI_ALG_SIG_SCHEME* target, BYTE** buffer, INT32* size, BOOL flag);
TPM_INLINE UINT16 TPMI_ALG_SIG_SCHEME_Marshal(
    TPMI_ALG_SIG_SCHEME* source, BYTE** buffer, INT32* size)
{
    return TPM_ALG_ID_Marshal((TPM_ALG_ID*)(source), (buffer), (size));
}

// Table "Definition of TPMI_ECC_KEY_EXCHANGE Type" (Part 2: Structures)
TPM_RC
TPMI_ECC_KEY_EXCHANGE_Unmarshal(
    TPMI_ECC_KEY_EXCHANGE* target, BYTE** buffer, INT32* size, BOOL flag);
TPM_INLINE UINT16 TPMI_ECC_KEY_EXCHANGE_Marshal(
    TPMI_ECC_KEY_EXCHANGE* source, BYTE** buffer, INT32* size)
{
    return TPM_ALG_ID_Marshal((TPM_ALG_ID*)(source), (buffer), (size));
}

// Table "Definition of TPMI_ST_COMMAND_TAG Type" (Part 2: Structures)
TPM_RC
TPMI_ST_COMMAND_TAG_Unmarshal(
    TPMI_ST_COMMAND_TAG* target, BYTE** buffer, INT32* size);
TPM_INLINE UINT16 TPMI_ST_COMMAND_TAG_Marshal(
    TPMI_ST_COMMAND_TAG* source, BYTE** buffer, INT32* size)
{
    return TPM_ST_Marshal((TPM_ST*)(source), (buffer), (size));
}

// Table "Definition of TPMI_ALG_MAC_SCHEME Type" (Part 2: Structures)
TPM_RC
TPMI_ALG_MAC_SCHEME_Unmarshal(
    TPMI_ALG_MAC_SCHEME* target, BYTE** buffer, INT32* size, BOOL flag);
TPM_INLINE UINT16 TPMI_ALG_MAC_SCHEME_Marshal(
    TPMI_ALG_MAC_SCHEME* source, BYTE** buffer, INT32* size)
{
    return TPM_ALG_ID_Marshal((TPM_ALG_ID*)(source), (buffer), (size));
}

// Table "Definition of TPMI_ALG_CIPHER_MODE Type" (Part 2: Structures)
TPM_RC
TPMI_ALG_CIPHER_MODE_Unmarshal(
    TPMI_ALG_CIPHER_MODE* target, BYTE** buffer, INT32* size, BOOL flag);
TPM_INLINE UINT16 TPMI_ALG_CIPHER_MODE_Marshal(
    TPMI_ALG_CIPHER_MODE* source, BYTE** buffer, INT32* size)
{
    return TPM_ALG_ID_Marshal((TPM_ALG_ID*)(source), (buffer), (size));
}

// Table "Definition of TPMS_EMPTY Structure" (Part 2: Structures)
TPM_RC
TPMS_EMPTY_Unmarshal(TPMS_EMPTY* target, BYTE** buffer, INT32* size);
UINT16
TPMS_EMPTY_Marshal(TPMS_EMPTY* source, BYTE** buffer, INT32* size);

// Table "Definition of TPMS_ALGORITHM_DESCRIPTION Structure" (Part 2: Structures)
UINT16
TPMS_ALGORITHM_DESCRIPTION_Marshal(
    TPMS_ALGORITHM_DESCRIPTION* source, BYTE** buffer, INT32* size);

// Table "Definition of TPMU_HA Union" (Part 2: Structures)
TPM_RC
TPMU_HA_Unmarshal(TPMU_HA* target, BYTE** buffer, INT32* size, UINT32 selector);
UINT16
TPMU_HA_Marshal(TPMU_HA* source, BYTE** buffer, INT32* size, UINT32 selector);

// Table "Definition of TPMT_HA Structure" (Part 2: Structures)
TPM_RC
TPMT_HA_Unmarshal(TPMT_HA* target, BYTE** buffer, INT32* size, BOOL flag);
UINT16
TPMT_HA_Marshal(TPMT_HA* source, BYTE** buffer, INT32* size);

// Table "Definition of TPM2B_DIGEST Structure" (Part 2: Structures)
TPM_RC
TPM2B_DIGEST_Unmarshal(TPM2B_DIGEST* target, BYTE** buffer, INT32* size);
UINT16
TPM2B_DIGEST_Marshal(TPM2B_DIGEST* source, BYTE** buffer, INT32* size);

// Table "Definition of TPM2B_DATA Structure" (Part 2: Structures)
TPM_RC
TPM2B_DATA_Unmarshal(TPM2B_DATA* target, BYTE** buffer, INT32* size);
UINT16
TPM2B_DATA_Marshal(TPM2B_DATA* source, BYTE** buffer, INT32* size);

// Table "Definition of Types for TPM2B_NONCE" (Part 2: Structures)
TPM_INLINE TPM_RC TPM2B_NONCE_Unmarshal(
    TPM2B_NONCE* target, BYTE** buffer, INT32* size)
{
    return TPM2B_DIGEST_Unmarshal((TPM2B_DIGEST*)(target), (buffer), (size));
}
TPM_INLINE UINT16 TPM2B_NONCE_Marshal(TPM2B_NONCE* source, BYTE** buffer, INT32* size)
{
    return TPM2B_DIGEST_Marshal((TPM2B_DIGEST*)(source), (buffer), (size));
}

// Table "Definition of Types for TPM2B_AUTH" (Part 2: Structures)
TPM_INLINE TPM_RC TPM2B_AUTH_Unmarshal(TPM2B_AUTH* target, BYTE** buffer, INT32* size)
{
    return TPM2B_DIGEST_Unmarshal((TPM2B_DIGEST*)(target), (buffer), (size));
}
TPM_INLINE UINT16 TPM2B_AUTH_Marshal(TPM2B_AUTH* source, BYTE** buffer, INT32* size)
{
    return TPM2B_DIGEST_Marshal((TPM2B_DIGEST*)(source), (buffer), (size));
}

// Table "Definition of Types for TPM2B_OPERAND" (Part 2: Structures)
TPM_INLINE TPM_RC TPM2B_OPERAND_Unmarshal(
    TPM2B_OPERAND* target, BYTE** buffer, INT32* size)
{
    return TPM2B_DIGEST_Unmarshal((TPM2B_DIGEST*)(target), (buffer), (size));
}
TPM_INLINE UINT16 TPM2B_OPERAND_Marshal(
    TPM2B_OPERAND* source, BYTE** buffer, INT32* size)
{
    return TPM2B_DIGEST_Marshal((TPM2B_DIGEST*)(source), (buffer), (size));
}

// Table "Definition of TPM2B_EVENT Structure" (Part 2: Structures)
TPM_RC
TPM2B_EVENT_Unmarshal(TPM2B_EVENT* target, BYTE** buffer, INT32* size);
UINT16
TPM2B_EVENT_Marshal(TPM2B_EVENT* source, BYTE** buffer, INT32* size);

// Table "Definition of TPM2B_MAX_BUFFER Structure" (Part 2: Structures)
TPM_RC
TPM2B_MAX_BUFFER_Unmarshal(TPM2B_MAX_BUFFER* target, BYTE** buffer, INT32* size);
UINT16
TPM2B_MAX_BUFFER_Marshal(TPM2B_MAX_BUFFER* source, BYTE** buffer, INT32* size);

// Table "Definition of TPM2B_MAX_NV_BUFFER Structure" (Part 2: Structures)
TPM_RC
TPM2B_MAX_NV_BUFFER_Unmarshal(
    TPM2B_MAX_NV_BUFFER* target, BYTE** buffer, INT32* size);
UINT16
TPM2B_MAX_NV_BUFFER_Marshal(TPM2B_MAX_NV_BUFFER* source, BYTE** buffer, INT32* size);

// Table "Definition of TPM2B_TIMEOUT Structure" (Part 2: Structures)
TPM_RC
TPM2B_TIMEOUT_Unmarshal(TPM2B_TIMEOUT* target, BYTE** buffer, INT32* size);
UINT16
TPM2B_TIMEOUT_Marshal(TPM2B_TIMEOUT* source, BYTE** buffer, INT32* size);

// Table "Definition of TPM2B_IV Structure" (Part 2: Structures)
TPM_RC
TPM2B_IV_Unmarshal(TPM2B_IV* target, BYTE** buffer, INT32* size);
UINT16
TPM2B_IV_Marshal(TPM2B_IV* source, BYTE** buffer, INT32* size);

// Table "Definition of TPM2B_VENDOR_PROPERTY Structure" (Part 2: Structures)
TPM_RC
TPM2B_VENDOR_PROPERTY_Unmarshal(
    TPM2B_VENDOR_PROPERTY* target, BYTE** buffer, INT32* size);
UINT16
TPM2B_VENDOR_PROPERTY_Marshal(
    TPM2B_VENDOR_PROPERTY* source, BYTE** buffer, INT32* size);

// Table "Definition of TPM2B_NAME Structure" (Part 2: Structures)
TPM_RC
TPM2B_NAME_Unmarshal(TPM2B_NAME* target, BYTE** buffer, INT32* size);
UINT16
TPM2B_NAME_Marshal(TPM2B_NAME* source, BYTE** buffer, INT32* size);

// Table "Definition of TPMS_PCR_SELECT Structure" (Part 2: Structures)
TPM_RC
TPMS_PCR_SELECT_Unmarshal(TPMS_PCR_SELECT* target, BYTE** buffer, INT32* size);
UINT16
TPMS_PCR_SELECT_Marshal(TPMS_PCR_SELECT* source, BYTE** buffer, INT32* size);

// Table "Definition of TPMS_PCR_SELECTION Structure" (Part 2: Structures)
TPM_RC
TPMS_PCR_SELECTION_Unmarshal(TPMS_PCR_SELECTION* target, BYTE** buffer, INT32* size);
UINT16
TPMS_PCR_SELECTION_Marshal(TPMS_PCR_SELECTION* source, BYTE** buffer, INT32* size);

// Table "Definition of TPMT_TK_CREATION Structure" (Part 2: Structures)
TPM_RC
TPMT_TK_CREATION_Unmarshal(TPMT_TK_CREATION* target, BYTE** buffer, INT32* size);
UINT16
TPMT_TK_CREATION_Marshal(TPMT_TK_CREATION* source, BYTE** buffer, INT32* size);

// Table "Definition of TPMT_TK_VERIFIED Structure" (Part 2: Structures)
TPM_RC
TPMT_TK_VERIFIED_Unmarshal(TPMT_TK_VERIFIED* target, BYTE** buffer, INT32* size);
UINT16
TPMT_TK_VERIFIED_Marshal(TPMT_TK_VERIFIED* source, BYTE** buffer, INT32* size);

// Table "Definition of TPMT_TK_AUTH Structure" (Part 2: Structures)
TPM_RC
TPMT_TK_AUTH_Unmarshal(TPMT_TK_AUTH* target, BYTE** buffer, INT32* size);
UINT16
TPMT_TK_AUTH_Marshal(TPMT_TK_AUTH* source, BYTE** buffer, INT32* size);

// Table "Definition of TPMT_TK_HASHCHECK Structure" (Part 2: Structures)
TPM_RC
TPMT_TK_HASHCHECK_Unmarshal(TPMT_TK_HASHCHECK* target, BYTE** buffer, INT32* size);
UINT16
TPMT_TK_HASHCHECK_Marshal(TPMT_TK_HASHCHECK* source, BYTE** buffer, INT32* size);

// Table "Definition of TPMS_ALG_PROPERTY Structure" (Part 2: Structures)
UINT16
TPMS_ALG_PROPERTY_Marshal(TPMS_ALG_PROPERTY* source, BYTE** buffer, INT32* size);

// Table "Definition of TPMS_TAGGED_PROPERTY Structure" (Part 2: Structures)
UINT16
TPMS_TAGGED_PROPERTY_Marshal(
    TPMS_TAGGED_PROPERTY* source, BYTE** buffer, INT32* size);

// Table "Definition of TPMS_TAGGED_PCR_SELECT Structure" (Part 2: Structures)
UINT16
TPMS_TAGGED_PCR_SELECT_Marshal(
    TPMS_TAGGED_PCR_SELECT* source, BYTE** buffer, INT32* size);

// Table "Definition of TPMS_TAGGED_POLICY Structure" (Part 2: Structures)
UINT16
TPMS_TAGGED_POLICY_Marshal(TPMS_TAGGED_POLICY* source, BYTE** buffer, INT32* size);

// Table "Definition of TPMS_ACT_DATA Structure" (Part 2: Structures)
UINT16
TPMS_ACT_DATA_Marshal(TPMS_ACT_DATA* source, BYTE** buffer, INT32* size);

#if SEC_CHANNEL_SUPPORT
// Table "Definition of TPMS_SPDM_SESSION_INFO Structure" (Part 2: Structures)
UINT16
TPMS_SPDM_SESSION_INFO_Marshal(
    TPMS_SPDM_SESSION_INFO* source, BYTE** buffer, INT32* size);
#endif  // SEC_CHANNEL_SUPPORT

// Table "Definition of TPML_CC Structure" (Part 2: Structures)
TPM_RC
TPML_CC_Unmarshal(TPML_CC* target, BYTE** buffer, INT32* size);
UINT16
TPML_CC_Marshal(TPML_CC* source, BYTE** buffer, INT32* size);

// Table "Definition of TPML_CCA Structure" (Part 2: Structures)
UINT16
TPML_CCA_Marshal(TPML_CCA* source, BYTE** buffer, INT32* size);

// Table "Definition of TPML_ALG Structure" (Part 2: Structures)
TPM_RC
TPML_ALG_Unmarshal(TPML_ALG* target, BYTE** buffer, INT32* size);
UINT16
TPML_ALG_Marshal(TPML_ALG* source, BYTE** buffer, INT32* size);

// Table "Definition of TPML_HANDLE Structure" (Part 2: Structures)
UINT16
TPML_HANDLE_Marshal(TPML_HANDLE* source, BYTE** buffer, INT32* size);

// Table "Definition of TPML_DIGEST Structure" (Part 2: Structures)
TPM_RC
TPML_DIGEST_Unmarshal(TPML_DIGEST* target, BYTE** buffer, INT32* size);
UINT16
TPML_DIGEST_Marshal(TPML_DIGEST* source, BYTE** buffer, INT32* size);

// Table "Definition of TPML_DIGEST_VALUES Structure" (Part 2: Structures)
TPM_RC
TPML_DIGEST_VALUES_Unmarshal(TPML_DIGEST_VALUES* target, BYTE** buffer, INT32* size);
UINT16
TPML_DIGEST_VALUES_Marshal(TPML_DIGEST_VALUES* source, BYTE** buffer, INT32* size);

// Table "Definition of TPML_PCR_SELECTION Structure" (Part 2: Structures)
TPM_RC
TPML_PCR_SELECTION_Unmarshal(TPML_PCR_SELECTION* target, BYTE** buffer, INT32* size);
UINT16
TPML_PCR_SELECTION_Marshal(TPML_PCR_SELECTION* source, BYTE** buffer, INT32* size);

// Table "Definition of TPML_ALG_PROPERTY Structure" (Part 2: Structures)
UINT16
TPML_ALG_PROPERTY_Marshal(TPML_ALG_PROPERTY* source, BYTE** buffer, INT32* size);

// Table "Definition of TPML_TAGGED_TPM_PROPERTY Structure" (Part 2: Structures)
UINT16
TPML_TAGGED_TPM_PROPERTY_Marshal(
    TPML_TAGGED_TPM_PROPERTY* source, BYTE** buffer, INT32* size);

// Table "Definition of TPML_TAGGED_PCR_PROPERTY Structure" (Part 2: Structures)
UINT16
TPML_TAGGED_PCR_PROPERTY_Marshal(
    TPML_TAGGED_PCR_PROPERTY* source, BYTE** buffer, INT32* size);

// Table "Definition of TPML_ECC_CURVE Structure" (Part 2: Structures)
#if ALG_ECC
UINT16
TPML_ECC_CURVE_Marshal(TPML_ECC_CURVE* source, BYTE** buffer, INT32* size);
#else  // ALG_ECC
#  define TPML_ECC_CURVE_Marshal UNIMPLEMENTED_Marshal
#endif  // ALG_ECC

// Table "Definition of TPML_TAGGED_POLICY Structure" (Part 2: Structures)
UINT16
TPML_TAGGED_POLICY_Marshal(TPML_TAGGED_POLICY* source, BYTE** buffer, INT32* size);

// Table "Definition of TPML_ACT_DATA Structure" (Part 2: Structures)
UINT16
TPML_ACT_DATA_Marshal(TPML_ACT_DATA* source, BYTE** buffer, INT32* size);

// Table "Definition of TPML_VENDOR_PROPERTY Structure" (Part 2: Structures)
TPM_RC
TPML_VENDOR_PROPERTY_Unmarshal(
    TPML_VENDOR_PROPERTY* target, BYTE** buffer, INT32* size);
UINT16
TPML_VENDOR_PROPERTY_Marshal(
    TPML_VENDOR_PROPERTY* source, BYTE** buffer, INT32* size);

// Table "Definition of TPMU_CAPABILITIES Union" (Part 2: Structures)
UINT16
TPMU_CAPABILITIES_Marshal(
    TPMU_CAPABILITIES* source, BYTE** buffer, INT32* size, UINT32 selector);

// Table "Definition of TPMS_CAPABILITY_DATA Structure" (Part 2: Structures)
UINT16
TPMS_CAPABILITY_DATA_Marshal(
    TPMS_CAPABILITY_DATA* source, BYTE** buffer, INT32* size);

// Table "Definition of TPMU_SET_CAPABILITIES Structure" (Part 2: Structures)
TPM_RC
TPMU_SET_CAPABILITIES_Unmarshal(
    TPMU_SET_CAPABILITIES* target, BYTE** buffer, INT32* size, UINT32 selector);

// Table "Definition of TPMS_SET_CAPABILITY_DATA Structure" (Part 2: Structures)
TPM_RC
TPMS_SET_CAPABILITY_DATA_Unmarshal(
    TPMS_SET_CAPABILITY_DATA* target, BYTE** buffer, INT32* size);

// Table "Definition of TPM2B_SET_CAPABILITY_DATA Structure" (Part 2: Structures)
TPM_RC
TPM2B_SET_CAPABILITY_DATA_Unmarshal(
    TPM2B_SET_CAPABILITY_DATA* target, BYTE** buffer, INT32* size);

// Table "Definition of TPMS_CLOCK_INFO Structure" (Part 2: Structures)
TPM_RC
TPMS_CLOCK_INFO_Unmarshal(TPMS_CLOCK_INFO* target, BYTE** buffer, INT32* size);
UINT16
TPMS_CLOCK_INFO_Marshal(TPMS_CLOCK_INFO* source, BYTE** buffer, INT32* size);

// Table "Definition of TPMS_TIME_INFO Structure" (Part 2: Structures)
TPM_RC
TPMS_TIME_INFO_Unmarshal(TPMS_TIME_INFO* target, BYTE** buffer, INT32* size);
UINT16
TPMS_TIME_INFO_Marshal(TPMS_TIME_INFO* source, BYTE** buffer, INT32* size);

// Table "Definition of TPMS_TIME_ATTEST_INFO Structure" (Part 2: Structures)
UINT16
TPMS_TIME_ATTEST_INFO_Marshal(
    TPMS_TIME_ATTEST_INFO* source, BYTE** buffer, INT32* size);

// Table "Definition of TPMS_CERTIFY_INFO Structure" (Part 2: Structures)
UINT16
TPMS_CERTIFY_INFO_Marshal(TPMS_CERTIFY_INFO* source, BYTE** buffer, INT32* size);

// Table "Definition of TPMS_QUOTE_INFO Structure" (Part 2: Structures)
UINT16
TPMS_QUOTE_INFO_Marshal(TPMS_QUOTE_INFO* source, BYTE** buffer, INT32* size);

// Table "Definition of TPMS_COMMAND_AUDIT_INFO Structure" (Part 2: Structures)
UINT16
TPMS_COMMAND_AUDIT_INFO_Marshal(
    TPMS_COMMAND_AUDIT_INFO* source, BYTE** buffer, INT32* size);

// Table "Definition of TPMS_SESSION_AUDIT_INFO Structure" (Part 2: Structures)
UINT16
TPMS_SESSION_AUDIT_INFO_Marshal(
    TPMS_SESSION_AUDIT_INFO* source, BYTE** buffer, INT32* size);

// Table "Definition of TPMS_CREATION_INFO Structure" (Part 2: Structures)
UINT16
TPMS_CREATION_INFO_Marshal(TPMS_CREATION_INFO* source, BYTE** buffer, INT32* size);

// Table "Definition of TPMS_NV_CERTIFY_INFO Structure" (Part 2: Structures)
UINT16
TPMS_NV_CERTIFY_INFO_Marshal(
    TPMS_NV_CERTIFY_INFO* source, BYTE** buffer, INT32* size);

// Table "Definition of TPMS_NV_DIGEST_CERTIFY_INFO Structure" (Part 2: Structures)
UINT16
TPMS_NV_DIGEST_CERTIFY_INFO_Marshal(
    TPMS_NV_DIGEST_CERTIFY_INFO* source, BYTE** buffer, INT32* size);

// Table "Definition of TPMI_ST_ATTEST Type" (Part 2: Structures)
TPM_INLINE UINT16 TPMI_ST_ATTEST_Marshal(
    TPMI_ST_ATTEST* source, BYTE** buffer, INT32* size)
{
    return TPM_ST_Marshal((TPM_ST*)(source), (buffer), (size));
}

// Table "Definition of TPMU_ATTEST Union" (Part 2: Structures)
UINT16
TPMU_ATTEST_Marshal(TPMU_ATTEST* source, BYTE** buffer, INT32* size, UINT32 selector);

// Table "Definition of TPMS_ATTEST Structure" (Part 2: Structures)
UINT16
TPMS_ATTEST_Marshal(TPMS_ATTEST* source, BYTE** buffer, INT32* size);

// Table "Definition of TPM2B_ATTEST Structure" (Part 2: Structures)
UINT16
TPM2B_ATTEST_Marshal(TPM2B_ATTEST* source, BYTE** buffer, INT32* size);

// Table "Definition of TPMS_AUTH_COMMAND Structure" (Part 2: Structures)
TPM_RC
TPMS_AUTH_COMMAND_Unmarshal(TPMS_AUTH_COMMAND* target, BYTE** buffer, INT32* size);

// Table "Definition of TPMS_AUTH_RESPONSE Structure" (Part 2: Structures)
UINT16
TPMS_AUTH_RESPONSE_Marshal(TPMS_AUTH_RESPONSE* source, BYTE** buffer, INT32* size);

// Table "Definition of TPMI_AES_KEY_BITS Type" (Part 2: Structures)
TPM_RC
TPMI_AES_KEY_BITS_Unmarshal(TPMI_AES_KEY_BITS* target, BYTE** buffer, INT32* size);
TPM_INLINE UINT16 TPMI_AES_KEY_BITS_Marshal(
    TPMI_AES_KEY_BITS* source, BYTE** buffer, INT32* size)
{
    return TPM_KEY_BITS_Marshal((TPM_KEY_BITS*)(source), (buffer), (size));
}
// Table "Definition of TPMI_SM4_KEY_BITS Type" (Part 2: Structures)
TPM_RC
TPMI_SM4_KEY_BITS_Unmarshal(TPMI_SM4_KEY_BITS* target, BYTE** buffer, INT32* size);
TPM_INLINE UINT16 TPMI_SM4_KEY_BITS_Marshal(
    TPMI_SM4_KEY_BITS* source, BYTE** buffer, INT32* size)
{
    return TPM_KEY_BITS_Marshal((TPM_KEY_BITS*)(source), (buffer), (size));
}

// Table "Definition of TPMI_CAMELLIA_KEY_BITS Type" (Part 2: Structures)
TPM_RC
TPMI_CAMELLIA_KEY_BITS_Unmarshal(
    TPMI_CAMELLIA_KEY_BITS* target, BYTE** buffer, INT32* size);
TPM_INLINE UINT16 TPMI_CAMELLIA_KEY_BITS_Marshal(
    TPMI_CAMELLIA_KEY_BITS* source, BYTE** buffer, INT32* size)
{
    return TPM_KEY_BITS_Marshal((TPM_KEY_BITS*)(source), (buffer), (size));
}

// Table "Definition of TPMU_SYM_KEY_BITS Union" (Part 2: Structures)
TPM_RC
TPMU_SYM_KEY_BITS_Unmarshal(
    TPMU_SYM_KEY_BITS* target, BYTE** buffer, INT32* size, UINT32 selector);
UINT16
TPMU_SYM_KEY_BITS_Marshal(
    TPMU_SYM_KEY_BITS* source, BYTE** buffer, INT32* size, UINT32 selector);

// Table "Definition of TPMU_SYM_MODE Union" (Part 2: Structures)
TPM_RC
TPMU_SYM_MODE_Unmarshal(
    TPMU_SYM_MODE* target, BYTE** buffer, INT32* size, UINT32 selector);
UINT16
TPMU_SYM_MODE_Marshal(
    TPMU_SYM_MODE* source, BYTE** buffer, INT32* size, UINT32 selector);

// Table "Definition of TPMT_SYM_DEF Structure" (Part 2: Structures)
TPM_RC
TPMT_SYM_DEF_Unmarshal(TPMT_SYM_DEF* target, BYTE** buffer, INT32* size, BOOL flag);
UINT16
TPMT_SYM_DEF_Marshal(TPMT_SYM_DEF* source, BYTE** buffer, INT32* size);

// Table "Definition of TPMT_SYM_DEF_OBJECT Structure" (Part 2: Structures)
TPM_RC
TPMT_SYM_DEF_OBJECT_Unmarshal(
    TPMT_SYM_DEF_OBJECT* target, BYTE** buffer, INT32* size, BOOL flag);
UINT16
TPMT_SYM_DEF_OBJECT_Marshal(TPMT_SYM_DEF_OBJECT* source, BYTE** buffer, INT32* size);

// Table "Definition of TPM2B_SYM_KEY Structure" (Part 2: Structures)
TPM_RC
TPM2B_SYM_KEY_Unmarshal(TPM2B_SYM_KEY* target, BYTE** buffer, INT32* size);
UINT16
TPM2B_SYM_KEY_Marshal(TPM2B_SYM_KEY* source, BYTE** buffer, INT32* size);

// Table "Definition of TPMS_SYMCIPHER_PARMS Structure" (Part 2: Structures)
TPM_RC
TPMS_SYMCIPHER_PARMS_Unmarshal(
    TPMS_SYMCIPHER_PARMS* target, BYTE** buffer, INT32* size);
UINT16
TPMS_SYMCIPHER_PARMS_Marshal(
    TPMS_SYMCIPHER_PARMS* source, BYTE** buffer, INT32* size);

// Table "Definition of TPM2B_LABEL Structure" (Part 2: Structures)
TPM_RC
TPM2B_LABEL_Unmarshal(TPM2B_LABEL* target, BYTE** buffer, INT32* size);
UINT16
TPM2B_LABEL_Marshal(TPM2B_LABEL* source, BYTE** buffer, INT32* size);

// Table "Definition of TPMS_DERIVE Structure" (Part 2: Structures)
TPM_RC
TPMS_DERIVE_Unmarshal(TPMS_DERIVE* target, BYTE** buffer, INT32* size);
UINT16
TPMS_DERIVE_Marshal(TPMS_DERIVE* source, BYTE** buffer, INT32* size);

// Table "Definition of TPM2B_DERIVE Structure" (Part 2: Structures)
TPM_RC
TPM2B_DERIVE_Unmarshal(TPM2B_DERIVE* target, BYTE** buffer, INT32* size);
UINT16
TPM2B_DERIVE_Marshal(TPM2B_DERIVE* source, BYTE** buffer, INT32* size);

// Table "Definition of TPM2B_SENSITIVE_DATA Structure" (Part 2: Structures)
TPM_RC
TPM2B_SENSITIVE_DATA_Unmarshal(
    TPM2B_SENSITIVE_DATA* target, BYTE** buffer, INT32* size);
UINT16
TPM2B_SENSITIVE_DATA_Marshal(
    TPM2B_SENSITIVE_DATA* source, BYTE** buffer, INT32* size);

// Table "Definition of TPMS_SENSITIVE_CREATE Structure" (Part 2: Structures)
TPM_RC
TPMS_SENSITIVE_CREATE_Unmarshal(
    TPMS_SENSITIVE_CREATE* target, BYTE** buffer, INT32* size);

// Table "Definition of TPM2B_SENSITIVE_CREATE Structure" (Part 2: Structures)
TPM_RC
TPM2B_SENSITIVE_CREATE_Unmarshal(
    TPM2B_SENSITIVE_CREATE* target, BYTE** buffer, INT32* size);

// Table "Definition of TPMS_SCHEME_HASH Structure" (Part 2: Structures)
TPM_RC
TPMS_SCHEME_HASH_Unmarshal(TPMS_SCHEME_HASH* target, BYTE** buffer, INT32* size);
UINT16
TPMS_SCHEME_HASH_Marshal(TPMS_SCHEME_HASH* source, BYTE** buffer, INT32* size);

// Table "Definition of TPMS_SCHEME_ECDAA Structure" (Part 2: Structures)
TPM_RC
TPMS_SCHEME_ECDAA_Unmarshal(TPMS_SCHEME_ECDAA* target, BYTE** buffer, INT32* size);
UINT16
TPMS_SCHEME_ECDAA_Marshal(TPMS_SCHEME_ECDAA* source, BYTE** buffer, INT32* size);

// Table "Definition of TPMI_ALG_KEYEDHASH_SCHEME Type" (Part 2: Structures)
TPM_RC
TPMI_ALG_KEYEDHASH_SCHEME_Unmarshal(
    TPMI_ALG_KEYEDHASH_SCHEME* target, BYTE** buffer, INT32* size, BOOL flag);
TPM_INLINE UINT16 TPMI_ALG_KEYEDHASH_SCHEME_Marshal(
    TPMI_ALG_KEYEDHASH_SCHEME* source, BYTE** buffer, INT32* size)
{
    return TPM_ALG_ID_Marshal((TPM_ALG_ID*)(source), (buffer), (size));
}

// Table "Definition of Types for HMAC_SIG_SCHEME" (Part 2: Structures)
TPM_INLINE TPM_RC TPMS_SCHEME_HMAC_Unmarshal(
    TPMS_SCHEME_HMAC* target, BYTE** buffer, INT32* size)
{
    return TPMS_SCHEME_HASH_Unmarshal((TPMS_SCHEME_HASH*)(target), (buffer), (size));
}
TPM_INLINE UINT16 TPMS_SCHEME_HMAC_Marshal(
    TPMS_SCHEME_HMAC* source, BYTE** buffer, INT32* size)
{
    return TPMS_SCHEME_HASH_Marshal((TPMS_SCHEME_HASH*)(source), (buffer), (size));
}

// Table "Definition of TPMS_SCHEME_XOR Structure" (Part 2: Structures)
TPM_RC
TPMS_SCHEME_XOR_Unmarshal(TPMS_SCHEME_XOR* target, BYTE** buffer, INT32* size);
UINT16
TPMS_SCHEME_XOR_Marshal(TPMS_SCHEME_XOR* source, BYTE** buffer, INT32* size);

// Table "Definition of TPMU_SCHEME_KEYEDHASH Union" (Part 2: Structures)
TPM_RC
TPMU_SCHEME_KEYEDHASH_Unmarshal(
    TPMU_SCHEME_KEYEDHASH* target, BYTE** buffer, INT32* size, UINT32 selector);
UINT16
TPMU_SCHEME_KEYEDHASH_Marshal(
    TPMU_SCHEME_KEYEDHASH* source, BYTE** buffer, INT32* size, UINT32 selector);

// Table "Definition of TPMT_KEYEDHASH_SCHEME Structure" (Part 2: Structures)
TPM_RC
TPMT_KEYEDHASH_SCHEME_Unmarshal(
    TPMT_KEYEDHASH_SCHEME* target, BYTE** buffer, INT32* size, BOOL flag);
UINT16
TPMT_KEYEDHASH_SCHEME_Marshal(
    TPMT_KEYEDHASH_SCHEME* source, BYTE** buffer, INT32* size);

// Table "Definition of Types for RSA Signature Schemes" (Part 2: Structures)
TPM_INLINE TPM_RC TPMS_SIG_SCHEME_RSASSA_Unmarshal(
    TPMS_SIG_SCHEME_RSASSA* target, BYTE** buffer, INT32* size)
{
    return TPMS_SCHEME_HASH_Unmarshal((TPMS_SCHEME_HASH*)(target), (buffer), (size));
}
TPM_INLINE UINT16 TPMS_SIG_SCHEME_RSASSA_Marshal(
    TPMS_SIG_SCHEME_RSASSA* source, BYTE** buffer, INT32* size)
{
    return TPMS_SCHEME_HASH_Marshal((TPMS_SCHEME_HASH*)(source), (buffer), (size));
}
TPM_INLINE TPM_RC TPMS_SIG_SCHEME_RSAPSS_Unmarshal(
    TPMS_SIG_SCHEME_RSAPSS* target, BYTE** buffer, INT32* size)
{
    return TPMS_SCHEME_HASH_Unmarshal((TPMS_SCHEME_HASH*)(target), (buffer), (size));
}
TPM_INLINE UINT16 TPMS_SIG_SCHEME_RSAPSS_Marshal(
    TPMS_SIG_SCHEME_RSAPSS* source, BYTE** buffer, INT32* size)
{
    return TPMS_SCHEME_HASH_Marshal((TPMS_SCHEME_HASH*)(source), (buffer), (size));
}

// Table "Definition of Types for ECC Signature Schemes" (Part 2: Structures)
TPM_INLINE TPM_RC TPMS_SIG_SCHEME_ECDSA_Unmarshal(
    TPMS_SIG_SCHEME_ECDSA* target, BYTE** buffer, INT32* size)
{
    return TPMS_SCHEME_HASH_Unmarshal((TPMS_SCHEME_HASH*)(target), (buffer), (size));
}
TPM_INLINE UINT16 TPMS_SIG_SCHEME_ECDSA_Marshal(
    TPMS_SIG_SCHEME_ECDSA* source, BYTE** buffer, INT32* size)
{
    return TPMS_SCHEME_HASH_Marshal((TPMS_SCHEME_HASH*)(source), (buffer), (size));
}
TPM_INLINE TPM_RC TPMS_SIG_SCHEME_ECDAA_Unmarshal(
    TPMS_SIG_SCHEME_ECDAA* target, BYTE** buffer, INT32* size)
{
    return TPMS_SCHEME_ECDAA_Unmarshal(
        (TPMS_SCHEME_ECDAA*)(target), (buffer), (size));
}
TPM_INLINE UINT16 TPMS_SIG_SCHEME_ECDAA_Marshal(
    TPMS_SIG_SCHEME_ECDAA* source, BYTE** buffer, INT32* size)
{
    return TPMS_SCHEME_ECDAA_Marshal((TPMS_SCHEME_ECDAA*)(source), (buffer), (size));
}
TPM_INLINE TPM_RC TPMS_SIG_SCHEME_SM2_Unmarshal(
    TPMS_SIG_SCHEME_SM2* target, BYTE** buffer, INT32* size)
{
    return TPMS_SCHEME_HASH_Unmarshal((TPMS_SCHEME_HASH*)(target), (buffer), (size));
}
TPM_INLINE UINT16 TPMS_SIG_SCHEME_SM2_Marshal(
    TPMS_SIG_SCHEME_SM2* source, BYTE** buffer, INT32* size)
{
    return TPMS_SCHEME_HASH_Marshal((TPMS_SCHEME_HASH*)(source), (buffer), (size));
}
TPM_INLINE TPM_RC TPMS_SIG_SCHEME_ECSCHNORR_Unmarshal(
    TPMS_SIG_SCHEME_ECSCHNORR* target, BYTE** buffer, INT32* size)
{
    return TPMS_SCHEME_HASH_Unmarshal((TPMS_SCHEME_HASH*)(target), (buffer), (size));
}
TPM_INLINE UINT16 TPMS_SIG_SCHEME_ECSCHNORR_Marshal(
    TPMS_SIG_SCHEME_ECSCHNORR* source, BYTE** buffer, INT32* size)
{
    return TPMS_SCHEME_HASH_Marshal((TPMS_SCHEME_HASH*)(source), (buffer), (size));
}
TPM_INLINE TPM_RC TPMS_SIG_SCHEME_EDDSA_Unmarshal(
    TPMS_SIG_SCHEME_EDDSA* target, BYTE** buffer, INT32* size)
{
    return TPMS_SCHEME_HASH_Unmarshal((TPMS_SCHEME_HASH*)(target), (buffer), (size));
}
TPM_INLINE UINT16 TPMS_SIG_SCHEME_EDDSA_Marshal(
    TPMS_SIG_SCHEME_EDDSA* source, BYTE** buffer, INT32* size)
{
    return TPMS_SCHEME_HASH_Marshal((TPMS_SCHEME_HASH*)(source), (buffer), (size));
}
TPM_INLINE TPM_RC TPMS_SIG_SCHEME_EDDSA_PH_Unmarshal(
    TPMS_SIG_SCHEME_EDDSA_PH* target, BYTE** buffer, INT32* size)
{
    return TPMS_SCHEME_HASH_Unmarshal((TPMS_SCHEME_HASH*)(target), (buffer), (size));
}
TPM_INLINE UINT16 TPMS_SIG_SCHEME_EDDSA_PH_Marshal(
    TPMS_SIG_SCHEME_EDDSA_PH* source, BYTE** buffer, INT32* size)
{
    return TPMS_SCHEME_HASH_Marshal((TPMS_SCHEME_HASH*)(source), (buffer), (size));
}

// Table "Definition of TPMU_SIG_SCHEME Union" (Part 2: Structures)
TPM_RC
TPMU_SIG_SCHEME_Unmarshal(
    TPMU_SIG_SCHEME* target, BYTE** buffer, INT32* size, UINT32 selector);
UINT16
TPMU_SIG_SCHEME_Marshal(
    TPMU_SIG_SCHEME* source, BYTE** buffer, INT32* size, UINT32 selector);

// Table "Definition of TPMT_SIG_SCHEME Structure" (Part 2: Structures)
TPM_RC
TPMT_SIG_SCHEME_Unmarshal(
    TPMT_SIG_SCHEME* target, BYTE** buffer, INT32* size, BOOL flag);
UINT16
TPMT_SIG_SCHEME_Marshal(TPMT_SIG_SCHEME* source, BYTE** buffer, INT32* size);

// Table "Definition of Types for Encryption Schemes" (Part 2: Structures)
TPM_INLINE TPM_RC TPMS_ENC_SCHEME_RSAES_Unmarshal(
    TPMS_ENC_SCHEME_RSAES* target, BYTE** buffer, INT32* size)
{
    return TPMS_EMPTY_Unmarshal((TPMS_EMPTY*)(target), (buffer), (size));
}
TPM_INLINE UINT16 TPMS_ENC_SCHEME_RSAES_Marshal(
    TPMS_ENC_SCHEME_RSAES* source, BYTE** buffer, INT32* size)
{
    return TPMS_EMPTY_Marshal((TPMS_EMPTY*)(source), (buffer), (size));
}
TPM_INLINE TPM_RC TPMS_ENC_SCHEME_OAEP_Unmarshal(
    TPMS_ENC_SCHEME_OAEP* target, BYTE** buffer, INT32* size)
{
    return TPMS_SCHEME_HASH_Unmarshal((TPMS_SCHEME_HASH*)(target), (buffer), (size));
}
TPM_INLINE UINT16 TPMS_ENC_SCHEME_OAEP_Marshal(
    TPMS_ENC_SCHEME_OAEP* source, BYTE** buffer, INT32* size)
{
    return TPMS_SCHEME_HASH_Marshal((TPMS_SCHEME_HASH*)(source), (buffer), (size));
}

// Table "Definition of Types for ECC Key Exchange" (Part 2: Structures)
TPM_INLINE TPM_RC TPMS_KEY_SCHEME_ECDH_Unmarshal(
    TPMS_KEY_SCHEME_ECDH* target, BYTE** buffer, INT32* size)
{
    return TPMS_SCHEME_HASH_Unmarshal((TPMS_SCHEME_HASH*)(target), (buffer), (size));
}
TPM_INLINE UINT16 TPMS_KEY_SCHEME_ECDH_Marshal(
    TPMS_KEY_SCHEME_ECDH* source, BYTE** buffer, INT32* size)
{
    return TPMS_SCHEME_HASH_Marshal((TPMS_SCHEME_HASH*)(source), (buffer), (size));
}
TPM_INLINE TPM_RC TPMS_KEY_SCHEME_SM2_Unmarshal(
    TPMS_KEY_SCHEME_SM2* target, BYTE** buffer, INT32* size)
{
    return TPMS_SCHEME_HASH_Unmarshal((TPMS_SCHEME_HASH*)(target), (buffer), (size));
}
TPM_INLINE UINT16 TPMS_KEY_SCHEME_SM2_Marshal(
    TPMS_KEY_SCHEME_SM2* source, BYTE** buffer, INT32* size)
{
    return TPMS_SCHEME_HASH_Marshal((TPMS_SCHEME_HASH*)(source), (buffer), (size));
}
TPM_INLINE TPM_RC TPMS_KEY_SCHEME_ECMQV_Unmarshal(
    TPMS_KEY_SCHEME_ECMQV* target, BYTE** buffer, INT32* size)
{
    return TPMS_SCHEME_HASH_Unmarshal((TPMS_SCHEME_HASH*)(target), (buffer), (size));
}
TPM_INLINE UINT16 TPMS_KEY_SCHEME_ECMQV_Marshal(
    TPMS_KEY_SCHEME_ECMQV* source, BYTE** buffer, INT32* size)
{
    return TPMS_SCHEME_HASH_Marshal((TPMS_SCHEME_HASH*)(source), (buffer), (size));
}

// Table "Definition of Types for KDF Schemes" (Part 2: Structures)
TPM_INLINE TPM_RC TPMS_KDF_SCHEME_MGF1_Unmarshal(
    TPMS_KDF_SCHEME_MGF1* target, BYTE** buffer, INT32* size)
{
    return TPMS_SCHEME_HASH_Unmarshal((TPMS_SCHEME_HASH*)(target), (buffer), (size));
}
TPM_INLINE UINT16 TPMS_KDF_SCHEME_MGF1_Marshal(
    TPMS_KDF_SCHEME_MGF1* source, BYTE** buffer, INT32* size)
{
    return TPMS_SCHEME_HASH_Marshal((TPMS_SCHEME_HASH*)(source), (buffer), (size));
}
TPM_INLINE TPM_RC TPMS_KDF_SCHEME_KDF1_SP800_56A_Unmarshal(
    TPMS_KDF_SCHEME_KDF1_SP800_56A* target, BYTE** buffer, INT32* size)
{
    return TPMS_SCHEME_HASH_Unmarshal((TPMS_SCHEME_HASH*)(target), (buffer), (size));
}
TPM_INLINE UINT16 TPMS_KDF_SCHEME_KDF1_SP800_56A_Marshal(
    TPMS_KDF_SCHEME_KDF1_SP800_56A* source, BYTE** buffer, INT32* size)
{
    return TPMS_SCHEME_HASH_Marshal((TPMS_SCHEME_HASH*)(source), (buffer), (size));
}
TPM_INLINE TPM_RC TPMS_KDF_SCHEME_KDF2_Unmarshal(
    TPMS_KDF_SCHEME_KDF2* target, BYTE** buffer, INT32* size)
{
    return TPMS_SCHEME_HASH_Unmarshal((TPMS_SCHEME_HASH*)(target), (buffer), (size));
}
TPM_INLINE UINT16 TPMS_KDF_SCHEME_KDF2_Marshal(
    TPMS_KDF_SCHEME_KDF2* source, BYTE** buffer, INT32* size)
{
    return TPMS_SCHEME_HASH_Marshal((TPMS_SCHEME_HASH*)(source), (buffer), (size));
}
TPM_INLINE TPM_RC TPMS_KDF_SCHEME_KDF1_SP800_108_Unmarshal(
    TPMS_KDF_SCHEME_KDF1_SP800_108* target, BYTE** buffer, INT32* size)
{
    return TPMS_SCHEME_HASH_Unmarshal((TPMS_SCHEME_HASH*)(target), (buffer), (size));
}
TPM_INLINE UINT16 TPMS_KDF_SCHEME_KDF1_SP800_108_Marshal(
    TPMS_KDF_SCHEME_KDF1_SP800_108* source, BYTE** buffer, INT32* size)
{
    return TPMS_SCHEME_HASH_Marshal((TPMS_SCHEME_HASH*)(source), (buffer), (size));
}

// Table "Definition of TPMU_KDF_SCHEME Union" (Part 2: Structures)
TPM_RC
TPMU_KDF_SCHEME_Unmarshal(
    TPMU_KDF_SCHEME* target, BYTE** buffer, INT32* size, UINT32 selector);
UINT16
TPMU_KDF_SCHEME_Marshal(
    TPMU_KDF_SCHEME* source, BYTE** buffer, INT32* size, UINT32 selector);

// Table "Definition of TPMT_KDF_SCHEME Structure" (Part 2: Structures)
TPM_RC
TPMT_KDF_SCHEME_Unmarshal(
    TPMT_KDF_SCHEME* target, BYTE** buffer, INT32* size, BOOL flag);
UINT16
TPMT_KDF_SCHEME_Marshal(TPMT_KDF_SCHEME* source, BYTE** buffer, INT32* size);

// Table "Definition of TPMI_ALG_ASYM_SCHEME Type" (Part 2: Structures)
TPM_RC
TPMI_ALG_ASYM_SCHEME_Unmarshal(
    TPMI_ALG_ASYM_SCHEME* target, BYTE** buffer, INT32* size, BOOL flag);
TPM_INLINE UINT16 TPMI_ALG_ASYM_SCHEME_Marshal(
    TPMI_ALG_ASYM_SCHEME* source, BYTE** buffer, INT32* size)
{
    return TPM_ALG_ID_Marshal((TPM_ALG_ID*)(source), (buffer), (size));
}

// Table "Definition of TPMU_ASYM_SCHEME Union" (Part 2: Structures)
TPM_RC
TPMU_ASYM_SCHEME_Unmarshal(
    TPMU_ASYM_SCHEME* target, BYTE** buffer, INT32* size, UINT32 selector);
UINT16
TPMU_ASYM_SCHEME_Marshal(
    TPMU_ASYM_SCHEME* source, BYTE** buffer, INT32* size, UINT32 selector);

// Table "Definition of TPMI_ALG_RSA_SCHEME Type" (Part 2: Structures)
TPM_RC
TPMI_ALG_RSA_SCHEME_Unmarshal(
    TPMI_ALG_RSA_SCHEME* target, BYTE** buffer, INT32* size, BOOL flag);
TPM_INLINE UINT16 TPMI_ALG_RSA_SCHEME_Marshal(
    TPMI_ALG_RSA_SCHEME* source, BYTE** buffer, INT32* size)
{
    return TPM_ALG_ID_Marshal((TPM_ALG_ID*)(source), (buffer), (size));
}

// Table "Definition of TPMT_RSA_SCHEME Structure" (Part 2: Structures)
TPM_RC
TPMT_RSA_SCHEME_Unmarshal(
    TPMT_RSA_SCHEME* target, BYTE** buffer, INT32* size, BOOL flag);
UINT16
TPMT_RSA_SCHEME_Marshal(TPMT_RSA_SCHEME* source, BYTE** buffer, INT32* size);

// Table "Definition of TPMI_ALG_RSA_DECRYPT Type" (Part 2: Structures)
TPM_RC
TPMI_ALG_RSA_DECRYPT_Unmarshal(
    TPMI_ALG_RSA_DECRYPT* target, BYTE** buffer, INT32* size, BOOL flag);
TPM_INLINE UINT16 TPMI_ALG_RSA_DECRYPT_Marshal(
    TPMI_ALG_RSA_DECRYPT* source, BYTE** buffer, INT32* size)
{
    return TPM_ALG_ID_Marshal((TPM_ALG_ID*)(source), (buffer), (size));
}

// Table "Definition of TPMT_RSA_DECRYPT Structure" (Part 2: Structures)
TPM_RC
TPMT_RSA_DECRYPT_Unmarshal(
    TPMT_RSA_DECRYPT* target, BYTE** buffer, INT32* size, BOOL flag);
UINT16
TPMT_RSA_DECRYPT_Marshal(TPMT_RSA_DECRYPT* source, BYTE** buffer, INT32* size);

// Table "Definition of TPM2B_PUBLIC_KEY_RSA Structure" (Part 2: Structures)
TPM_RC
TPM2B_PUBLIC_KEY_RSA_Unmarshal(
    TPM2B_PUBLIC_KEY_RSA* target, BYTE** buffer, INT32* size);
UINT16
TPM2B_PUBLIC_KEY_RSA_Marshal(
    TPM2B_PUBLIC_KEY_RSA* source, BYTE** buffer, INT32* size);

// Table "Definition of TPMI_RSA_KEY_BITS Type" (Part 2: Structures)
TPM_RC
TPMI_RSA_KEY_BITS_Unmarshal(TPMI_RSA_KEY_BITS* target, BYTE** buffer, INT32* size);
TPM_INLINE UINT16 TPMI_RSA_KEY_BITS_Marshal(
    TPMI_RSA_KEY_BITS* source, BYTE** buffer, INT32* size)
{
    return TPM_KEY_BITS_Marshal((TPM_KEY_BITS*)(source), (buffer), (size));
}

// Table "Definition of TPM2B_PRIVATE_KEY_RSA Structure" (Part 2: Structures)
TPM_RC
TPM2B_PRIVATE_KEY_RSA_Unmarshal(
    TPM2B_PRIVATE_KEY_RSA* target, BYTE** buffer, INT32* size);
UINT16
TPM2B_PRIVATE_KEY_RSA_Marshal(
    TPM2B_PRIVATE_KEY_RSA* source, BYTE** buffer, INT32* size);

// Table "Definition of TPM2B_ECC_PARAMETER Structure" (Part 2: Structures)
TPM_RC
TPM2B_ECC_PARAMETER_Unmarshal(
    TPM2B_ECC_PARAMETER* target, BYTE** buffer, INT32* size);
UINT16
TPM2B_ECC_PARAMETER_Marshal(TPM2B_ECC_PARAMETER* source, BYTE** buffer, INT32* size);

// Table "Definition of TPMS_ECC_POINT Structure" (Part 2: Structures)
TPM_RC
TPMS_ECC_POINT_Unmarshal(TPMS_ECC_POINT* target, BYTE** buffer, INT32* size);
UINT16
TPMS_ECC_POINT_Marshal(TPMS_ECC_POINT* source, BYTE** buffer, INT32* size);

// Table "Definition of TPM2B_ECC_POINT Structure" (Part 2: Structures)
TPM_RC
TPM2B_ECC_POINT_Unmarshal(TPM2B_ECC_POINT* target, BYTE** buffer, INT32* size);
UINT16
TPM2B_ECC_POINT_Marshal(TPM2B_ECC_POINT* source, BYTE** buffer, INT32* size);

// Table "Definition of TPMI_ALG_ECC_SCHEME Type" (Part 2: Structures)
TPM_RC
TPMI_ALG_ECC_SCHEME_Unmarshal(
    TPMI_ALG_ECC_SCHEME* target, BYTE** buffer, INT32* size, BOOL flag);
TPM_INLINE UINT16 TPMI_ALG_ECC_SCHEME_Marshal(
    TPMI_ALG_ECC_SCHEME* source, BYTE** buffer, INT32* size)
{
    return TPM_ALG_ID_Marshal((TPM_ALG_ID*)(source), (buffer), (size));
}

// Table "Definition of TPMI_ECC_CURVE Type" (Part 2: Structures)
TPM_RC
TPMI_ECC_CURVE_Unmarshal(
    TPMI_ECC_CURVE* target, BYTE** buffer, INT32* size, BOOL flag);
TPM_INLINE UINT16 TPMI_ECC_CURVE_Marshal(
    TPMI_ECC_CURVE* source, BYTE** buffer, INT32* size)
{
    return TPM_ECC_CURVE_Marshal((TPM_ECC_CURVE*)(source), (buffer), (size));
}

// Table "Definition of TPMT_ECC_SCHEME Structure" (Part 2: Structures)
TPM_RC
TPMT_ECC_SCHEME_Unmarshal(
    TPMT_ECC_SCHEME* target, BYTE** buffer, INT32* size, BOOL flag);
UINT16
TPMT_ECC_SCHEME_Marshal(TPMT_ECC_SCHEME* source, BYTE** buffer, INT32* size);

// Table "Definition of TPMS_ALGORITHM_DETAIL_ECC Structure" (Part 2: Structures)
UINT16
TPMS_ALGORITHM_DETAIL_ECC_Marshal(
    TPMS_ALGORITHM_DETAIL_ECC* source, BYTE** buffer, INT32* size);

// Table "Definition of TPMS_SIGNATURE_RSA Structure" (Part 2: Structures)
TPM_RC
TPMS_SIGNATURE_RSA_Unmarshal(TPMS_SIGNATURE_RSA* target, BYTE** buffer, INT32* size);
UINT16
TPMS_SIGNATURE_RSA_Marshal(TPMS_SIGNATURE_RSA* source, BYTE** buffer, INT32* size);

// Table "Definition of Types for Signature" (Part 2: Structures)
TPM_INLINE TPM_RC TPMS_SIGNATURE_RSASSA_Unmarshal(
    TPMS_SIGNATURE_RSASSA* target, BYTE** buffer, INT32* size)
{
    return TPMS_SIGNATURE_RSA_Unmarshal(
        (TPMS_SIGNATURE_RSA*)(target), (buffer), (size));
}
TPM_INLINE UINT16 TPMS_SIGNATURE_RSASSA_Marshal(
    TPMS_SIGNATURE_RSASSA* source, BYTE** buffer, INT32* size)
{
    return TPMS_SIGNATURE_RSA_Marshal(
        (TPMS_SIGNATURE_RSA*)(source), (buffer), (size));
}
TPM_INLINE TPM_RC TPMS_SIGNATURE_RSAPSS_Unmarshal(
    TPMS_SIGNATURE_RSAPSS* target, BYTE** buffer, INT32* size)
{
    return TPMS_SIGNATURE_RSA_Unmarshal(
        (TPMS_SIGNATURE_RSA*)(target), (buffer), (size));
}
TPM_INLINE UINT16 TPMS_SIGNATURE_RSAPSS_Marshal(
    TPMS_SIGNATURE_RSAPSS* source, BYTE** buffer, INT32* size)
{
    return TPMS_SIGNATURE_RSA_Marshal(
        (TPMS_SIGNATURE_RSA*)(source), (buffer), (size));
}

// Table "Definition of TPMS_SIGNATURE_ECC Structure" (Part 2: Structures)
TPM_RC
TPMS_SIGNATURE_ECC_Unmarshal(TPMS_SIGNATURE_ECC* target, BYTE** buffer, INT32* size);
UINT16
TPMS_SIGNATURE_ECC_Marshal(TPMS_SIGNATURE_ECC* source, BYTE** buffer, INT32* size);

// Table "Definition of Types for TPMS_SIGNATURE_ECC" (Part 2: Structures)
TPM_INLINE TPM_RC TPMS_SIGNATURE_ECDSA_Unmarshal(
    TPMS_SIGNATURE_ECDSA* target, BYTE** buffer, INT32* size)
{
    return TPMS_SIGNATURE_ECC_Unmarshal(
        (TPMS_SIGNATURE_ECC*)(target), (buffer), (size));
}
TPM_INLINE UINT16 TPMS_SIGNATURE_ECDSA_Marshal(
    TPMS_SIGNATURE_ECDSA* source, BYTE** buffer, INT32* size)
{
    return TPMS_SIGNATURE_ECC_Marshal(
        (TPMS_SIGNATURE_ECC*)(source), (buffer), (size));
}
TPM_INLINE TPM_RC TPMS_SIGNATURE_ECDAA_Unmarshal(
    TPMS_SIGNATURE_ECDAA* target, BYTE** buffer, INT32* size)
{
    return TPMS_SIGNATURE_ECC_Unmarshal(
        (TPMS_SIGNATURE_ECC*)(target), (buffer), (size));
}
TPM_INLINE UINT16 TPMS_SIGNATURE_ECDAA_Marshal(
    TPMS_SIGNATURE_ECDAA* source, BYTE** buffer, INT32* size)
{
    return TPMS_SIGNATURE_ECC_Marshal(
        (TPMS_SIGNATURE_ECC*)(source), (buffer), (size));
}
TPM_INLINE TPM_RC TPMS_SIGNATURE_SM2_Unmarshal(
    TPMS_SIGNATURE_SM2* target, BYTE** buffer, INT32* size)
{
    return TPMS_SIGNATURE_ECC_Unmarshal(
        (TPMS_SIGNATURE_ECC*)(target), (buffer), (size));
}
TPM_INLINE UINT16 TPMS_SIGNATURE_SM2_Marshal(
    TPMS_SIGNATURE_SM2* source, BYTE** buffer, INT32* size)
{
    return TPMS_SIGNATURE_ECC_Marshal(
        (TPMS_SIGNATURE_ECC*)(source), (buffer), (size));
}
TPM_INLINE TPM_RC TPMS_SIGNATURE_ECSCHNORR_Unmarshal(
    TPMS_SIGNATURE_ECSCHNORR* target, BYTE** buffer, INT32* size)
{
    return TPMS_SIGNATURE_ECC_Unmarshal(
        (TPMS_SIGNATURE_ECC*)(target), (buffer), (size));
}
TPM_INLINE UINT16 TPMS_SIGNATURE_ECSCHNORR_Marshal(
    TPMS_SIGNATURE_ECSCHNORR* source, BYTE** buffer, INT32* size)
{
    return TPMS_SIGNATURE_ECC_Marshal(
        (TPMS_SIGNATURE_ECC*)(source), (buffer), (size));
}
TPM_INLINE TPM_RC TPMS_SIGNATURE_EDDSA_Unmarshal(
    TPMS_SIGNATURE_EDDSA* target, BYTE** buffer, INT32* size)
{
    return TPMS_SIGNATURE_ECC_Unmarshal(
        (TPMS_SIGNATURE_ECC*)(target), (buffer), (size));
}
TPM_INLINE UINT16 TPMS_SIGNATURE_EDDSA_Marshal(
    TPMS_SIGNATURE_EDDSA* source, BYTE** buffer, INT32* size)
{
    return TPMS_SIGNATURE_ECC_Marshal(
        (TPMS_SIGNATURE_ECC*)(source), (buffer), (size));
}
TPM_INLINE TPM_RC TPMS_SIGNATURE_EDDSA_PH_Unmarshal(
    TPMS_SIGNATURE_EDDSA_PH* target, BYTE** buffer, INT32* size)
{
    return TPMS_SIGNATURE_ECC_Unmarshal(
        (TPMS_SIGNATURE_ECC*)(target), (buffer), (size));
}
TPM_INLINE UINT16 TPMS_SIGNATURE_EDDSA_PH_Marshal(
    TPMS_SIGNATURE_EDDSA_PH* source, BYTE** buffer, INT32* size)
{
    return TPMS_SIGNATURE_ECC_Marshal(
        (TPMS_SIGNATURE_ECC*)(source), (buffer), (size));
}

// Table "Definition of TPMU_SIGNATURE Union" (Part 2: Structures)
TPM_RC
TPMU_SIGNATURE_Unmarshal(
    TPMU_SIGNATURE* target, BYTE** buffer, INT32* size, UINT32 selector);
UINT16
TPMU_SIGNATURE_Marshal(
    TPMU_SIGNATURE* source, BYTE** buffer, INT32* size, UINT32 selector);

// Table "Definition of TPMT_SIGNATURE Structure" (Part 2: Structures)
TPM_RC
TPMT_SIGNATURE_Unmarshal(
    TPMT_SIGNATURE* target, BYTE** buffer, INT32* size, BOOL flag);
UINT16
TPMT_SIGNATURE_Marshal(TPMT_SIGNATURE* source, BYTE** buffer, INT32* size);

// Table "Definition of TPMU_ENCRYPTED_SECRET Union" (Part 2: Structures)
TPM_RC
TPMU_ENCRYPTED_SECRET_Unmarshal(
    TPMU_ENCRYPTED_SECRET* target, BYTE** buffer, INT32* size, UINT32 selector);
UINT16
TPMU_ENCRYPTED_SECRET_Marshal(
    TPMU_ENCRYPTED_SECRET* source, BYTE** buffer, INT32* size, UINT32 selector);

// Table "Definition of TPM2B_ENCRYPTED_SECRET Structure" (Part 2: Structures)
TPM_RC
TPM2B_ENCRYPTED_SECRET_Unmarshal(
    TPM2B_ENCRYPTED_SECRET* target, BYTE** buffer, INT32* size);
UINT16
TPM2B_ENCRYPTED_SECRET_Marshal(
    TPM2B_ENCRYPTED_SECRET* source, BYTE** buffer, INT32* size);

// Table "Definition of TPMI_ALG_PUBLIC Type" (Part 2: Structures)
TPM_RC
TPMI_ALG_PUBLIC_Unmarshal(TPMI_ALG_PUBLIC* target, BYTE** buffer, INT32* size);
TPM_INLINE UINT16 TPMI_ALG_PUBLIC_Marshal(
    TPMI_ALG_PUBLIC* source, BYTE** buffer, INT32* size)
{
    return TPM_ALG_ID_Marshal((TPM_ALG_ID*)(source), (buffer), (size));
}

// Table "Definition of TPMU_PUBLIC_ID Union" (Part 2: Structures)
TPM_RC
TPMU_PUBLIC_ID_Unmarshal(
    TPMU_PUBLIC_ID* target, BYTE** buffer, INT32* size, UINT32 selector);
UINT16
TPMU_PUBLIC_ID_Marshal(
    TPMU_PUBLIC_ID* source, BYTE** buffer, INT32* size, UINT32 selector);

// Table "Definition of TPMS_KEYEDHASH_PARMS Structure" (Part 2: Structures)
TPM_RC
TPMS_KEYEDHASH_PARMS_Unmarshal(
    TPMS_KEYEDHASH_PARMS* target, BYTE** buffer, INT32* size);
UINT16
TPMS_KEYEDHASH_PARMS_Marshal(
    TPMS_KEYEDHASH_PARMS* source, BYTE** buffer, INT32* size);

// Table "Definition of TPMS_RSA_PARMS Structure" (Part 2: Structures)
TPM_RC
TPMS_RSA_PARMS_Unmarshal(TPMS_RSA_PARMS* target, BYTE** buffer, INT32* size);
UINT16
TPMS_RSA_PARMS_Marshal(TPMS_RSA_PARMS* source, BYTE** buffer, INT32* size);

// Table "Definition of TPMS_ECC_PARMS Structure" (Part 2: Structures)
TPM_RC
TPMS_ECC_PARMS_Unmarshal(TPMS_ECC_PARMS* target, BYTE** buffer, INT32* size);
UINT16
TPMS_ECC_PARMS_Marshal(TPMS_ECC_PARMS* source, BYTE** buffer, INT32* size);

// Table "Definition of TPMU_PUBLIC_PARMS Union" (Part 2: Structures)
TPM_RC
TPMU_PUBLIC_PARMS_Unmarshal(
    TPMU_PUBLIC_PARMS* target, BYTE** buffer, INT32* size, UINT32 selector);
UINT16
TPMU_PUBLIC_PARMS_Marshal(
    TPMU_PUBLIC_PARMS* source, BYTE** buffer, INT32* size, UINT32 selector);

// Table "Definition of TPMT_PUBLIC_PARMS Structure" (Part 2: Structures)
TPM_RC
TPMT_PUBLIC_PARMS_Unmarshal(TPMT_PUBLIC_PARMS* target, BYTE** buffer, INT32* size);
UINT16
TPMT_PUBLIC_PARMS_Marshal(TPMT_PUBLIC_PARMS* source, BYTE** buffer, INT32* size);

// Table "Definition of TPMT_PUBLIC Structure" (Part 2: Structures)
TPM_RC
TPMT_PUBLIC_Unmarshal(TPMT_PUBLIC* target, BYTE** buffer, INT32* size, BOOL flag);
UINT16
TPMT_PUBLIC_Marshal(TPMT_PUBLIC* source, BYTE** buffer, INT32* size);

// Table "Definition of TPM2B_PUBLIC Structure" (Part 2: Structures)
TPM_RC
TPM2B_PUBLIC_Unmarshal(TPM2B_PUBLIC* target, BYTE** buffer, INT32* size, BOOL flag);
UINT16
TPM2B_PUBLIC_Marshal(TPM2B_PUBLIC* source, BYTE** buffer, INT32* size);

// Table "Definition of TPM2B_TEMPLATE Structure" (Part 2: Structures)
TPM_RC
TPM2B_TEMPLATE_Unmarshal(TPM2B_TEMPLATE* target, BYTE** buffer, INT32* size);
UINT16
TPM2B_TEMPLATE_Marshal(TPM2B_TEMPLATE* source, BYTE** buffer, INT32* size);

// Table "Definition of TPM2B_PRIVATE_VENDOR_SPECIFIC Structure" (Part 2: Structures)
TPM_RC
TPM2B_PRIVATE_VENDOR_SPECIFIC_Unmarshal(
    TPM2B_PRIVATE_VENDOR_SPECIFIC* target, BYTE** buffer, INT32* size);
UINT16
TPM2B_PRIVATE_VENDOR_SPECIFIC_Marshal(
    TPM2B_PRIVATE_VENDOR_SPECIFIC* source, BYTE** buffer, INT32* size);

// Table "Definition of TPMU_SENSITIVE_COMPOSITE Union" (Part 2: Structures)
TPM_RC
TPMU_SENSITIVE_COMPOSITE_Unmarshal(
    TPMU_SENSITIVE_COMPOSITE* target, BYTE** buffer, INT32* size, UINT32 selector);
UINT16
TPMU_SENSITIVE_COMPOSITE_Marshal(
    TPMU_SENSITIVE_COMPOSITE* source, BYTE** buffer, INT32* size, UINT32 selector);

// Table "Definition of TPMT_SENSITIVE Structure" (Part 2: Structures)
TPM_RC
TPMT_SENSITIVE_Unmarshal(TPMT_SENSITIVE* target, BYTE** buffer, INT32* size);
UINT16
TPMT_SENSITIVE_Marshal(TPMT_SENSITIVE* source, BYTE** buffer, INT32* size);

// Table "Definition of TPM2B_SENSITIVE Structure" (Part 2: Structures)
TPM_RC
TPM2B_SENSITIVE_Unmarshal(TPM2B_SENSITIVE* target, BYTE** buffer, INT32* size);
UINT16
TPM2B_SENSITIVE_Marshal(TPM2B_SENSITIVE* source, BYTE** buffer, INT32* size);

// Table "Definition of TPM2B_PRIVATE Structure" (Part 2: Structures)
TPM_RC
TPM2B_PRIVATE_Unmarshal(TPM2B_PRIVATE* target, BYTE** buffer, INT32* size);
UINT16
TPM2B_PRIVATE_Marshal(TPM2B_PRIVATE* source, BYTE** buffer, INT32* size);

// Table "Definition of TPM2B_ID_OBJECT Structure" (Part 2: Structures)
TPM_RC
TPM2B_ID_OBJECT_Unmarshal(TPM2B_ID_OBJECT* target, BYTE** buffer, INT32* size);
UINT16
TPM2B_ID_OBJECT_Marshal(TPM2B_ID_OBJECT* source, BYTE** buffer, INT32* size);

// Table "Definition of TPM_NT Constants" (Part 2: Structures)
// Table "Definition of TPMS_NV_PIN_COUNTER_PARAMETERS Structure" (Part 2: Structures)
TPM_RC
TPMS_NV_PIN_COUNTER_PARAMETERS_Unmarshal(
    TPMS_NV_PIN_COUNTER_PARAMETERS* target, BYTE** buffer, INT32* size);
UINT16
TPMS_NV_PIN_COUNTER_PARAMETERS_Marshal(
    TPMS_NV_PIN_COUNTER_PARAMETERS* source, BYTE** buffer, INT32* size);

// Table "Definition of TPMA_NV Bits" (Part 2: Structures)
TPM_RC
TPMA_NV_Unmarshal(TPMA_NV* target, BYTE** buffer, INT32* size);
TPM_INLINE UINT16 TPMA_NV_Marshal(TPMA_NV* source, BYTE** buffer, INT32* size)
{
    return UINT32_Marshal((UINT32*)(source), (buffer), (size));
}

// Table "Definition of TPMA_NV_EXP Bits" (Part 2: Structures)
TPM_RC
TPMA_NV_EXP_Unmarshal(TPMA_NV_EXP* target, BYTE** buffer, INT32* size);
TPM_INLINE UINT16 TPMA_NV_EXP_Marshal(TPMA_NV_EXP* source, BYTE** buffer, INT32* size)
{
    return UINT64_Marshal((UINT64*)(source), (buffer), (size));
}

// Table "Definition of TPMS_NV_PUBLIC Structure" (Part 2: Structures)
TPM_RC
TPMS_NV_PUBLIC_Unmarshal(TPMS_NV_PUBLIC* target, BYTE** buffer, INT32* size);
UINT16
TPMS_NV_PUBLIC_Marshal(TPMS_NV_PUBLIC* source, BYTE** buffer, INT32* size);

// Table "Definition of TPM2B_NV_PUBLIC Structure" (Part 2: Structures)
TPM_RC
TPM2B_NV_PUBLIC_Unmarshal(TPM2B_NV_PUBLIC* target, BYTE** buffer, INT32* size);
UINT16
TPM2B_NV_PUBLIC_Marshal(TPM2B_NV_PUBLIC* source, BYTE** buffer, INT32* size);

// Table "Definition of TPMS_NV_PUBLIC_EXP_ATTR Structure" (Part 2: Structures)
TPM_RC
TPMS_NV_PUBLIC_EXP_ATTR_Unmarshal(
    TPMS_NV_PUBLIC_EXP_ATTR* target, BYTE** buffer, INT32* size);
UINT16
TPMS_NV_PUBLIC_EXP_ATTR_Marshal(
    TPMS_NV_PUBLIC_EXP_ATTR* source, BYTE** buffer, INT32* size);

// Table "Definition of TPMU_NV_PUBLIC_2 Union" (Part 2: Structures)
TPM_RC
TPMU_NV_PUBLIC_2_Unmarshal(
    TPMU_NV_PUBLIC_2* target, BYTE** buffer, INT32* size, UINT32 selector);
UINT16
TPMU_NV_PUBLIC_2_Marshal(
    TPMU_NV_PUBLIC_2* source, BYTE** buffer, INT32* size, UINT32 selector);

// Table "Definition of TPMT_NV_PUBLIC_2 Structure" (Part 2: Structures)
TPM_RC
TPMT_NV_PUBLIC_2_Unmarshal(TPMT_NV_PUBLIC_2* target, BYTE** buffer, INT32* size);
UINT16
TPMT_NV_PUBLIC_2_Marshal(TPMT_NV_PUBLIC_2* source, BYTE** buffer, INT32* size);

// Table "Definition of TPM2B_NV_PUBLIC_2 Structure" (Part 2: Structures)
TPM_RC
TPM2B_NV_PUBLIC_2_Unmarshal(TPM2B_NV_PUBLIC_2* target, BYTE** buffer, INT32* size);
UINT16
TPM2B_NV_PUBLIC_2_Marshal(TPM2B_NV_PUBLIC_2* source, BYTE** buffer, INT32* size);

// Table "Definition of TPM2B_CONTEXT_SENSITIVE Structure" (Part 2: Structures)
TPM_RC
TPM2B_CONTEXT_SENSITIVE_Unmarshal(
    TPM2B_CONTEXT_SENSITIVE* target, BYTE** buffer, INT32* size);
UINT16
TPM2B_CONTEXT_SENSITIVE_Marshal(
    TPM2B_CONTEXT_SENSITIVE* source, BYTE** buffer, INT32* size);

// Table "Definition of TPMS_CONTEXT_DATA Structure" (Part 2: Structures)
TPM_RC
TPMS_CONTEXT_DATA_Unmarshal(TPMS_CONTEXT_DATA* target, BYTE** buffer, INT32* size);
UINT16
TPMS_CONTEXT_DATA_Marshal(TPMS_CONTEXT_DATA* source, BYTE** buffer, INT32* size);

// Table "Definition of TPM2B_CONTEXT_DATA Structure" (Part 2: Structures)
TPM_RC
TPM2B_CONTEXT_DATA_Unmarshal(TPM2B_CONTEXT_DATA* target, BYTE** buffer, INT32* size);
UINT16
TPM2B_CONTEXT_DATA_Marshal(TPM2B_CONTEXT_DATA* source, BYTE** buffer, INT32* size);

// Table "Definition of TPMS_CONTEXT Structure" (Part 2: Structures)
TPM_RC
TPMS_CONTEXT_Unmarshal(TPMS_CONTEXT* target, BYTE** buffer, INT32* size);
UINT16
TPMS_CONTEXT_Marshal(TPMS_CONTEXT* source, BYTE** buffer, INT32* size);

// Table "Definition of TPMS_CREATION_DATA Structure" (Part 2: Structures)
UINT16
TPMS_CREATION_DATA_Marshal(TPMS_CREATION_DATA* source, BYTE** buffer, INT32* size);

// Table "Definition of TPM2B_CREATION_DATA Structure" (Part 2: Structures)
UINT16
TPM2B_CREATION_DATA_Marshal(TPM2B_CREATION_DATA* source, BYTE** buffer, INT32* size);

// Table "Definition of TPM_AT Constants" (Part 2: Structures)
TPM_RC
TPM_AT_Unmarshal(TPM_AT* target, BYTE** buffer, INT32* size);
TPM_INLINE UINT16 TPM_AT_Marshal(TPM_AT* source, BYTE** buffer, INT32* size)
{
    return UINT32_Marshal((UINT32*)(source), (buffer), (size));
}

// Table "Definition of TPM_AE Constants" (Part 2: Structures)
TPM_INLINE UINT16 TPM_AE_Marshal(TPM_AE* source, BYTE** buffer, INT32* size)
{
    return UINT32_Marshal((UINT32*)(source), (buffer), (size));
}

// Table "Definition of TPMS_AC_OUTPUT Structure" (Part 2: Structures)
UINT16
TPMS_AC_OUTPUT_Marshal(TPMS_AC_OUTPUT* source, BYTE** buffer, INT32* size);

// Table "Definition of TPML_AC_CAPABILITIES Structure" (Part 2: Structures)
UINT16
TPML_AC_CAPABILITIES_Marshal(
    TPML_AC_CAPABILITIES* source, BYTE** buffer, INT32* size);

// For structures that unmarshals/marshals an array, the code calls an
// un/marshaling function to process the array of the defined type.
// This section contains the functions that perform that operation
// Array Unmarshal/Marshal for BYTE
TPM_RC
BYTE_Array_Unmarshal(BYTE* target, BYTE** buffer, INT32* size, INT32 count);
UINT16
BYTE_Array_Marshal(BYTE* source, BYTE** buffer, INT32* size, INT32 count);

// Array Unmarshal and Marshal for TPM_ALG_ID
TPM_RC
TPM_ALG_ID_Array_Unmarshal(
    TPM_ALG_ID* target, BYTE** buffer, INT32* size, INT32 count);
UINT16
TPM_ALG_ID_Array_Marshal(TPM_ALG_ID* source, BYTE** buffer, INT32* size, INT32 count);

// Array Unmarshal and Marshal for TPM_CC
TPM_RC
TPM_CC_Array_Unmarshal(TPM_CC* target, BYTE** buffer, INT32* size, INT32 count);
UINT16
TPM_CC_Array_Marshal(TPM_CC* source, BYTE** buffer, INT32* size, INT32 count);

// Array Marshal for TPM_ECC_CURVE
#if ALG_ECC
UINT16
TPM_ECC_CURVE_Array_Marshal(
    TPM_ECC_CURVE* source, BYTE** buffer, INT32* size, INT32 count);
#else  // ALG_ECC
#  define TPM_ECC_CURVE_Array_Marshal UNIMPLEMENTED_Marshal
#endif  // ALG_ECC

// Array Marshal for TPM_HANDLE
UINT16
TPM_HANDLE_Array_Marshal(TPM_HANDLE* source, BYTE** buffer, INT32* size, INT32 count);

// Array Unmarshal and Marshal for TPM2B_DIGEST
TPM_RC
TPM2B_DIGEST_Array_Unmarshal(
    TPM2B_DIGEST* target, BYTE** buffer, INT32* size, INT32 count);
UINT16
TPM2B_DIGEST_Array_Marshal(
    TPM2B_DIGEST* source, BYTE** buffer, INT32* size, INT32 count);

// Array Unmarshal and Marshal for TPM2B_VENDOR_PROPERTY
TPM_RC
TPM2B_VENDOR_PROPERTY_Array_Unmarshal(
    TPM2B_VENDOR_PROPERTY* target, BYTE** buffer, INT32* size, INT32 count);
UINT16
TPM2B_VENDOR_PROPERTY_Array_Marshal(
    TPM2B_VENDOR_PROPERTY* source, BYTE** buffer, INT32* size, INT32 count);

// Array Marshal for TPMA_CC
UINT16
TPMA_CC_Array_Marshal(TPMA_CC* source, BYTE** buffer, INT32* size, INT32 count);

// Array Marshal for TPMS_AC_OUTPUT
UINT16
TPMS_AC_OUTPUT_Array_Marshal(
    TPMS_AC_OUTPUT* source, BYTE** buffer, INT32* size, INT32 count);

// Array Marshal for TPMS_ACT_DATA
UINT16
TPMS_ACT_DATA_Array_Marshal(
    TPMS_ACT_DATA* source, BYTE** buffer, INT32* size, INT32 count);

// Array Marshal for TPMS_ALG_PROPERTY
UINT16
TPMS_ALG_PROPERTY_Array_Marshal(
    TPMS_ALG_PROPERTY* source, BYTE** buffer, INT32* size, INT32 count);

// Array Unmarshal and Marshal for TPMS_PCR_SELECTION
TPM_RC
TPMS_PCR_SELECTION_Array_Unmarshal(
    TPMS_PCR_SELECTION* target, BYTE** buffer, INT32* size, INT32 count);
UINT16
TPMS_PCR_SELECTION_Array_Marshal(
    TPMS_PCR_SELECTION* source, BYTE** buffer, INT32* size, INT32 count);

// Array Marshal for TPMS_TAGGED_PCR_SELECT
UINT16
TPMS_TAGGED_PCR_SELECT_Array_Marshal(
    TPMS_TAGGED_PCR_SELECT* source, BYTE** buffer, INT32* size, INT32 count);

// Array Marshal for TPMS_TAGGED_POLICY
UINT16
TPMS_TAGGED_POLICY_Array_Marshal(
    TPMS_TAGGED_POLICY* source, BYTE** buffer, INT32* size, INT32 count);

// Array Marshal for TPMS_TAGGED_PROPERTY
UINT16
TPMS_TAGGED_PROPERTY_Array_Marshal(
    TPMS_TAGGED_PROPERTY* source, BYTE** buffer, INT32* size, INT32 count);

// Array Unmarshal and Marshal for TPMT_HA
TPM_RC
TPMT_HA_Array_Unmarshal(
    TPMT_HA* target, BYTE** buffer, INT32* size, BOOL flag, INT32 count);
UINT16
TPMT_HA_Array_Marshal(TPMT_HA* source, BYTE** buffer, INT32* size, INT32 count);

#if SEC_CHANNEL_SUPPORT
// Array Marshal for TPM2B_PUBLIC
UINT16
TPM2B_PUBLIC_Array_Marshal(
    TPM2B_PUBLIC* source, BYTE** buffer, INT32* size, INT32 count);

// Array Marshal for TPMS_SPDM_SESSION_INFO
UINT16
TPMS_SPDM_SESSION_INFO_Array_Marshal(
    TPMS_SPDM_SESSION_INFO* source, BYTE** buffer, INT32* size, INT32 count);
#endif  // SEC_CHANNEL_SUPPORT

#endif  // _MARSHAL_FP_H_
