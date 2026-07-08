// This file contains the build switches. This contains switches for multiple
// versions of the crypto-library so some may not apply to your environment.
//

#ifndef _COMPILER_DEPENDENCIES_H_
#define _COMPILER_DEPENDENCIES_H_

#if defined(__GNUC__)
#  include "CompilerDependencies_gcc.h"
#elif defined(_MSC_VER)
#  include "CompilerDependencies_msvc.h"
#else
#  error unexpected
#endif

#include <stdint.h>
#include <stddef.h>

// Things that are not defined should be defined as <empty>

#ifndef NORETURN
#  define NORETURN
#endif
#ifndef LIB_EXPORT
#  define LIB_EXPORT
#endif
#ifndef LIB_IMPORT
#  define LIB_IMPORT
#endif
#ifndef _REDUCE_WARNING_LEVEL_
#  define _REDUCE_WARNING_LEVEL_(n)
#endif
#ifndef _NORMAL_WARNING_LEVEL_
#  define _NORMAL_WARNING_LEVEL_
#endif
#ifndef NOT_REFERENCED
#  define NOT_REFERENCED(x) ((void)(x))
#endif

#ifdef _POSIX_
typedef int SOCKET;
#endif

#if !defined(TPM_STATIC_ASSERT) || !defined(COMPILER_CHECKS)
#  error Expect definitions of COMPILER_CHECKS and TPM_STATIC_ASSERT
#elif COMPILER_CHECKS
// pre static_assert static_assert
#  define MUST_BE(e) TPM_STATIC_ASSERT(e)

#else
// intentionally disabled, fine.
#  define MUST_BE(e)
#endif

#endif  // _COMPILER_DEPENDENCIES_H_
