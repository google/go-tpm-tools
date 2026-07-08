
//** Introduction
//
// This header file is used to 'splice' the wolfcrypt library into the TPM code.

#ifndef SYM_LIB_DEFINED
#define SYM_LIB_DEFINED

#define SYM_LIB_WOLF

#include <wolfssl/wolfcrypt/aes.h>

//***************************************************************
//** Links to the wolfCrypt AES code
//***************************************************************
#if ALG_SM4
#  error "Wolf doesn't support SM4"
#endif

#if ALG_CAMELLIA
#  error "Wolf doesn't support Camellia"
#endif

// Define the order of parameters to the library functions that do block encryption
// and decryption.
typedef void (*TpmCryptSetSymKeyCall_t)(void* keySchedule, BYTE* out, const BYTE* in);

// The Crypt functions that call the block encryption function use the parameters
// in the order:
//  1) keySchedule
//  2) in buffer
//  3) out buffer
// Since wolfcrypt uses the order in encryptoCall_t above, need to swizzle the
// values to the order required by the library.
#define SWIZZLE(keySchedule, in, out) \
    (void*)(keySchedule), (BYTE*)(out), (const BYTE*)(in)

// Macros to set up the encryption/decryption key schedules
//
// AES:
#define TpmCryptSetEncryptKeyAES(key, keySizeInBits, schedule) \
    wc_AesSetKeyDirect((tpmKeyScheduleAES*)(schedule),         \
                       key,                                    \
                       BITS_TO_BYTES(keySizeInBits),           \
                       0,                                      \
                       AES_ENCRYPTION)
#define TpmCryptSetDecryptKeyAES(key, keySizeInBits, schedule) \
    wc_AesSetKeyDirect((tpmKeyScheduleAES*)(schedule),         \
                       key,                                    \
                       BITS_TO_BYTES(keySizeInBits),           \
                       0,                                      \
                       AES_DECRYPTION)

// Macros to alias encryption calls to specific algorithms. This should be used
// sparingly. Currently, only used by CryptRand.c
//
// When using these calls, to call the AES block encryption code, the caller
// should use:
//      TpmCryptEncryptAES(SWIZZLE(keySchedule, in, out));
#define TpmCryptEncryptAES wc_AesEncryptDirect
#define TpmCryptDecryptAES wc_AesDecryptDirect
#define tpmKeyScheduleAES  Aes

typedef union tpmCryptKeySchedule_t tpmCryptKeySchedule_t;

// This definition would change if there were something to report
#define SymLibSimulationEnd()

#endif  // SYM_LIB_DEFINED
