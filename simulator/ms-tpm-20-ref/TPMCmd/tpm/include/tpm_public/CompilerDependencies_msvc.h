// This file contains compiler specific switches.
// These definitions are for the Microsoft compiler
//

#ifndef _COMPILER_DEPENDENCIES_MSVC_H_
#define _COMPILER_DEPENDENCIES_MSVC_H_

#if !defined(_MSC_VER)
#  error CompilerDependencies_msvc.h included for wrong compiler
#endif

// Endian conversion for aligned structures
#define REVERSE_ENDIAN_16(_Number) _byteswap_ushort(_Number)
#define REVERSE_ENDIAN_32(_Number) _byteswap_ulong(_Number)
#define REVERSE_ENDIAN_64(_Number) _byteswap_uint64(_Number)

// Avoid compiler warning for in line of stdio (or not)
//#define _NO_CRT_STDIO_INLINE

// This macro is used to handle LIB_EXPORT of function and variable names in lieu
// of a .def file. Visual Studio requires that functions be explicitly exported and
// imported.
#ifdef TPM_AS_DLL
#  define LIB_EXPORT __declspec(dllexport)  // VS compatible version
#  define LIB_IMPORT __declspec(dllimport)
#else
// building static libraries
#  define LIB_EXPORT
#  define LIB_IMPORT
#endif

#define TPM_INLINE inline

// This is defined to indicate a function that does not return. Microsoft compilers
// do not support the _Noreturn function parameter.
#define NORETURN __declspec(noreturn)
#if _MSC_VER >= 1400  // SAL processing when needed
#  include <sal.h>
#endif

// #  ifdef _WIN64
// #    define _INTPTR 2
// #  else
// #    define _INTPTR 1
// #  endif

#define NOT_REFERENCED(x) ((void)(x))

// Lower the compiler error warning for system include
// files. They tend not to be that clean and there is no
// reason to sort through all the spurious errors that they
// generate when the normal error level is set to /Wall
#define _REDUCE_WARNING_LEVEL_(n) __pragma(warning(push, n))
// Restore the compiler warning level
#define _NORMAL_WARNING_LEVEL_ __pragma(warning(pop))

#ifdef TPM_STATIC_ASSERT
#  error TPM_STATIC_ASSERT already defined
#endif

// MSVC: failure results in error C2118: negative subscript error
#define TPM_STATIC_ASSERT(e) typedef char __C_ASSERT__[(e) ? 1 : -1]

#endif  // _COMPILER_DEPENDENCIES_MSVC_H_
