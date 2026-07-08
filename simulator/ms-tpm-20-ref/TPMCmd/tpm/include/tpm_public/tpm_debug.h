
#ifndef _TPM_DEBUG_H_
#define _TPM_DEBUG_H_

#include <platform_interface/tpm_to_platform_interface.h>

// Basic Debug Printing
#if ENABLE_TPM_DEBUG_PRINT

#  define TPM_DEBUG_PRINT(s)                 _plat_debug_print(s)
#  define TPM_DEBUG_PRINT_BUFFER(buf, size)  _plat_debug_print_buffer(buf, size)
#  define TPM_DEBUG_PRINT_INT32(name, value) _plat_debug_print_int32(name, value)
#  define TPM_DEBUG_PRINT_INT64(name, value) _plat_debug_print_int64(name, value)
// use the TPM_DEBUG_PRINTF versions only if there are extra arguments.
// GCC doesn't support an empty variable list, use TPM_DEBUG_PRINT instead.
#  define TPM_DEBUG_PRINTF(s, ...) _plat_debug_printf(s, __VA_ARGS__)
#  define TPM_DEBUG_SNPRINTF(buf, bufsize, s, ...) \
      _plat_debug_snprintf(buf, bufsize, s, __VA_ARGS__)

#else

#  define TPM_DEBUG_PRINT(s)
#  define TPM_DEBUG_PRINT_BUFFER(buf, size)
#  define TPM_DEBUG_PRINT_INT32(name, value)
#  define TPM_DEBUG_PRINT_INT64(name, value)
#  define TPM_DEBUG_PRINTF(s, ...)
#  define TPM_DEBUG_SNPRINTF(buf, bufsize, s, ...)

#endif  // ENABLE_TPM_DEBUG_PRINT

// Verbose Code Path tracing
#if ENABLE_TPM_DEBUG_TRACE && ENABLE_TPM_DEBUG_PRINT

#  define TPM_DEBUG_TRACEX(extra) \
      TPM_DEBUG_PRINT(__func__);  \
      TPM_DEBUG_PRINT(extra)

#  define TPM_DEBUG_TRACE() TPM_DEBUG_PRINT(__func__)

#else

#  define TPM_DEBUG_TRACEX(s)
#  define TPM_DEBUG_TRACE()

#endif  // ENABLE_TPM_DEBUG_TRACE && ENABLE_TPM_DEBUG_PRINT

// Low Level Crypto Debugging
#if ENABLE_TPM_DEBUG_PRINT && ENABLE_CRYPTO_DEBUG

// these functions are not declared here, but expect to be declared where these macros are consumed.
#  define TPM_DEBUG_PRINT_BIGNUM(name, value) _bnDebug_printBigNum(name, value);
#  define TPM_DEBUG_PRINT_BIGNUM_FULL(name, value) \
      _bnDebug_printBigNumFull(name, value);
#  define TPM_DEBUG_PRINT_BIGPOINT(name, value) _bnDebug_printBigPoint(name, value);
#  define TPM_DEBUG_PRINT_TPMS_ECC_POINT(name, value) \
      _bnDebug_printTPMS_ECC_POINT(name, value);
#  define TPM_DEBUG_PRINT_TPM2B(name, value, reverse) \
      _bnDebug_printTpm2B(name, value, reverse);

//#error SHOULD BE OFF

#else

#  define TPM_DEBUG_PRINT_BIGNUM(name, value)
#  define TPM_DEBUG_PRINT_BIGNUM_FULL(name, value)
#  define TPM_DEBUG_PRINT_BIGPOINT(name, value)
#  define TPM_DEBUG_PRINT_TPMS_ECC_POINT(name, value)
#  define TPM_DEBUG_PRINT_TPM2B(name, value, reverse)

#endif

#endif  //_TPM_DEBUG_H_
