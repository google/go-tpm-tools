//** Description
// This file will instance the TPM variables that are not stack allocated.

// Descriptions of global variables are in Global.h. There macro macro definitions
// that allows a variable to be instanced or simply defined as an external variable.
// When global.h is included from this .c file, GLOBAL_C is defined and values are
// instanced (and possibly initialized), but when global.h is included by any other
// file, they are simply defined as external values. DO NOT DEFINE GLOBAL_C IN ANY
// OTHER FILE.
//
// NOTE: This is a change from previous implementations where Global.h just contained
// the extern declaration and values were instanced in this file. This change keeps
// the definition and instance in one file making maintenance easier. The instanced
// data will still be in the global.obj file.
//
// The OIDs.h file works in a way that is similar to the Global.h with the definition
// of the values in OIDs.h such that they are instanced in global.obj. The macros
// that are defined in Global.h are used in OIDs.h in the same way as they are in
// Global.h.

//** Defines and Includes
#define GLOBAL_C
#include "Tpm.h"
#include "OIDs.h"

#if CC_CertifyX509
#  include "X509.h"
#endif  // CC_CertifyX509

// Global string constants for consistency in KDF function calls.
// These string constants are shared across functions to make sure that they
// are all using consistent string values.

// each instance must define a different struct since the buffer sizes vary.
#define TPM2B_STRING(name, value)                                   \
    typedef union name##_                                           \
    {                                                               \
        struct                                                      \
        {                                                           \
            UINT16 size;                                            \
            BYTE   buffer[sizeof(value)];                           \
        } t;                                                        \
        TPM2B b;                                                    \
    } TPM2B_##name##_;                                              \
    const TPM2B_##name##_ name##_data = {{sizeof(value), {value}}}; \
    const TPM2B*          name        = &name##_data.b

TPM2B_STRING(PRIMARY_OBJECT_CREATION, "Primary Object Creation");
TPM2B_STRING(CFB_KEY, "CFB");
TPM2B_STRING(CONTEXT_KEY, "CONTEXT");
TPM2B_STRING(INTEGRITY_KEY, "INTEGRITY");
TPM2B_STRING(SECRET_KEY, "SECRET");
TPM2B_STRING(HIERARCHY_PROOF_SECRET_LABEL, "H_PROOF_SECRET");
TPM2B_STRING(HIERARCHY_SEED_SECRET_LABEL, "H_SEED_SECRET");
TPM2B_STRING(HIERARCHY_FW_SECRET_LABEL, "H_FW_SECRET");
TPM2B_STRING(HIERARCHY_SVN_SECRET_LABEL, "H_SVN_SECRET");
TPM2B_STRING(SESSION_KEY, "ATH");
TPM2B_STRING(STORAGE_KEY, "STORAGE");
TPM2B_STRING(XOR_KEY, "XOR");
TPM2B_STRING(COMMIT_STRING, "ECDAA Commit");
TPM2B_STRING(DUPLICATE_STRING, "DUPLICATE");
TPM2B_STRING(IDENTITY_STRING, "IDENTITY");
TPM2B_STRING(OBFUSCATE_STRING, "OBFUSCATE");
#if ENABLE_SELF_TESTS
TPM2B_STRING(OAEP_TEST_STRING, "OAEP Test Value");
#endif  // ENABLE_SELF_TESTS

//*** g_rcIndex[]
const UINT16 g_rcIndex[15]  = {TPM_RC_1,
                               TPM_RC_2,
                               TPM_RC_3,
                               TPM_RC_4,
                               TPM_RC_5,
                               TPM_RC_6,
                               TPM_RC_7,
                               TPM_RC_8,
                               TPM_RC_9,
                               TPM_RC_A,
                               TPM_RC_B,
                               TPM_RC_C,
                               TPM_RC_D,
                               TPM_RC_E,
                               TPM_RC_F};

BOOL         g_manufactured = FALSE;
BOOL         g_initCompleted = FALSE;
