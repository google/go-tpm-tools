//** Introduction
// This file defines error codes used in failure macros in the TPM Core Library.
// This file is part of TpmConfiguration because the Platform library can add error
// codes of it's own, and ultimately the specific error codes are a vendor decision
// because TPM2_GetTestResult returns manufacturer-defined data in failure mode.
// The only thing in this file that must be consistent with a vendor's implementation
// are the _names_ of error codes used by the core library.  Even the values can
// change and are only a suggestion.

#ifndef _TPMPROFILE_ERRORCODES_H
#define _TPMPROFILE_ERRORCODES_H

// turn off clang-format because alignment doesn't persist across comments
// with current settings
// clang-format off

#define FATAL_ERROR_ALLOCATION       (1)
#define FATAL_ERROR_DIVIDE_ZERO      (2)
#define FATAL_ERROR_INTERNAL         (3)
#define FATAL_ERROR_PARAMETER        (4)
#define FATAL_ERROR_ENTROPY          (5)
#define FATAL_ERROR_SELF_TEST        (6)
#define FATAL_ERROR_CRYPTO           (7)
#define FATAL_ERROR_NV_UNRECOVERABLE (8)

// indicates that the TPM has been re-manufactured after an
// unrecoverable NV error
#define FATAL_ERROR_REMANUFACTURED   (9)
#define FATAL_ERROR_DRBG             (10)
#define FATAL_ERROR_MOVE_SIZE        (11)
#define FATAL_ERROR_COUNTER_OVERFLOW (12)
#define FATAL_ERROR_SUBTRACT         (13)
#define FATAL_ERROR_MATHLIBRARY      (14)
// end of codes defined through v1.52

// leave space for numbers that may have been used by vendors or platforms.
// Ultimately this file and these ranges are only a suggestion because
// TPM2_GetTestResult returns manufacturer-defined data in failure mode.
// Reserve 15-499
#define FATAL_ERROR_RESERVED_START   (15)
#define FATAL_ERROR_RESERVED_END     (499)

// Additional error codes defined by TPM library:
#define FATAL_ERROR_ASSERT           (500)
#define FATAL_ERROR_NV_INIT          (501)
#define FATAL_ERROR_CRYPTO_INIT      (502)
#define FATAL_ERROR_NO_INIT          (503)

// Platform library violated interface contract.
#define FATAL_ERROR_PLATFORM         (600)

// Test/Simulator errors 1000+
#define FATAL_ERROR_FORCED           (1000)

#endif  // _TPMPROFILE_ERRORCODES_H
