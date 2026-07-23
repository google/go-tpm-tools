
/* TPM specific preprocessor flags for wolfcrypt */

#ifndef WOLF_CRYPT_USER_SETTINGS_H
#define WOLF_CRYPT_USER_SETTINGS_H

/* Remove the automatic setting of the default I/O functions EmbedSend()
    and EmbedReceive(). */
#define WOLFSSL_USER_IO

/* Avoid naming conflicts */
#define NO_OLD_WC_NAMES

/* Use stack based fast math for all big integer math */
#define USE_FAST_MATH
#define TFM_TIMING_RESISTANT

/* Expose direct encryption functions */
#define WOLFSSL_AES_DIRECT

/* Enable/Disable algorithm support based on TPM implementation header */
#if ALG_SHA256
#  define WOLFSSL_SHA256
#endif
#if ALG_SHA384 || ALG_SHA512
#  define WOLFSSL_SHA384
#  define WOLFSSL_SHA512
#endif
#if ALG_RSA
/* Turn on RSA key generation functionality */
#  define WOLFSSL_KEY_GEN
#endif
#if ALG_ECC || defined(WOLFSSL_LIB)
#  define HAVE_ECC

/* Expose additional ECC primitives */
#  define WOLFSSL_PUBLIC_ECC_ADD_DBL
#  define ECC_TIMING_RESISTANT

/* Enables Shamir calc method */
#  define ECC_SHAMIR

/* The TPM only needs low level ECC crypto */
#  define NO_ECC_SIGN
#  define NO_ECC_VERIFY
#  define NO_ECC_SECP

#  undef ECC_BN_P256
#  undef ECC_SM2_P256
#  undef ECC_BN_P638
#  define ECC_BN_P256  NO
#  define ECC_SM2_P256 NO
#  define ECC_BN_P638  NO

#endif

/* Disable explicit RSA. The TPM support for RSA is dependent only on TFM */
#define NO_RSA
#define NO_RC4
#define NO_ASN

/* Enable debug wolf library check */
//#define LIBRARY_COMPATIBILITY_CHECK

#define WOLFSSL_

#endif  // WOLF_CRYPT_USER_SETTINGS_H
