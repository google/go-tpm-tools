// This file contains compiler specific switches.
// These definitions are for the GCC compiler
//

#ifndef _COMPILER_DEPENDENCIES_GCC_H_
#define _COMPILER_DEPENDENCIES_GCC_H_

#if !defined(__GNUC__)
#  error CompilerDependencies_gcc.h included for wrong compiler
#endif

// silence specific GCC errors
#pragma GCC diagnostic push
// don't warn on unused local typedefs, they are used as a
// cross-compiler static_assert
#pragma GCC diagnostic ignored "-Wunused-local-typedefs"

// This is needed when compiling against OpenSSL 3.0, as the Ossl bindings use:
//  - EC_POINT_set_affine_coordinates_GFp / EC_POINTs_mul
//  - AES_set_encrypt_key / AES_encrypt
//  - Camellia_set_key / Camellia_encrypt
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

#undef _MSC_VER
#undef WIN32

#ifndef WINAPI
#  define WINAPI
#endif
#ifndef __pragma
#  define __pragma(x)
#endif
#define REVERSE_ENDIAN_16(_Number) __builtin_bswap16(_Number)
#define REVERSE_ENDIAN_32(_Number) __builtin_bswap32(_Number)
#define REVERSE_ENDIAN_64(_Number) __builtin_bswap64(_Number)

#define NORETURN __attribute__((noreturn))

#define TPM_INLINE inline __attribute__((always_inline))

#ifdef __cplusplus
// c++ needed for google test
#  define TPM_STATIC_ASSERT(e) static_assert(e, "static assert")
#else
#  define TPM_STATIC_ASSERT(e) _Static_assert(e, "static assert")
#endif
#endif  // _COMPILER_DEPENDENCIES_H_
