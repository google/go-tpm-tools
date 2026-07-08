//
// This verifies that information expected from the consumer's TpmConfiguration is
// set properly and consistently.
//
#ifndef _VERIFY_CONFIGURATION_H
#define _VERIFY_CONFIGURATION_H

MUST_BE(YES == 1);
MUST_BE(NO == 0);

// verify these defines are either YES or NO.
#define MUST_BE_0_OR_1(x) MUST_BE(((x) == NO) || ((x) == YES))
#define MUST_BE_0(x)      MUST_BE((x) == NO)
#define MUST_BE_1(x)      MUST_BE((x) == YES)

// Debug Options
MUST_BE_0_OR_1(DEBUG);
MUST_BE_0_OR_1(SIMULATION);
MUST_BE_0_OR_1(ENABLE_TPM_DEBUG_PRINT);
MUST_BE_0_OR_1(DRBG_DEBUG_PRINT);
MUST_BE_0_OR_1(CERTIFYX509_DEBUG);
MUST_BE_0_OR_1(USE_DEBUG_RNG);

// RSA Debug Options
MUST_BE_0_OR_1(RSA_INSTRUMENT);
MUST_BE_0_OR_1(USE_RSA_KEY_CACHE);
MUST_BE_0_OR_1(USE_KEY_CACHE_FILE);

// Test Options
MUST_BE_0_OR_1(ALLOW_FORCE_FAILURE_MODE);

// Internal checks
MUST_BE_0_OR_1(LIBRARY_COMPATIBILITY_CHECK);
MUST_BE_0_OR_1(COMPILER_CHECKS);
MUST_BE_0_OR_1(RUNTIME_SIZE_CHECKS);

// Compliance options
MUST_BE_0_OR_1(FIPS_COMPLIANT);
MUST_BE_0_OR_1(USE_SPEC_COMPLIANT_PROOFS);
MUST_BE_0_OR_1(SKIP_PROOF_ERRORS);

// Implementation alternatives - should not change external behavior
MUST_BE_0_OR_1(TABLE_DRIVEN_MARSHAL);
MUST_BE_0_OR_1(RSA_KEY_SIEVE);

// Implementation alternatives - changes external behavior
MUST_BE_0_OR_1(LONGJMP_SUPPORTED);
MUST_BE_0_OR_1(_DRBG_STATE_SAVE);
MUST_BE_0_OR_1(USE_DA_USED);
MUST_BE_0_OR_1(ENABLE_SELF_TESTS);
MUST_BE_0_OR_1(CLOCK_STOPS);
MUST_BE_0_OR_1(ACCUMULATE_SELF_HEAL_TIMER);
MUST_BE_0_OR_1(FAIL_TRACE);

// Vendor alternatives
// Check VENDOR_PERMANENT_AUTH_ENABLED & VENDOR_PERMANENT_AUTH_HANDLE are consistent
MUST_BE_0_OR_1(VENDOR_PERMANENT_AUTH_ENABLED);

#if VENDOR_PERMANENT_AUTH_ENABLED == YES
#  if !defined(VENDOR_PERMANENT_AUTH_HANDLE)           \
      || VENDOR_PERMANENT_AUTH_HANDLE < TPM_RH_AUTH_00 \
      || VENDOR_PERMANENT_AUTH_HANDLE > TPM_RH_AUTH_FF
#    error VENDOR_PERMANENT_AUTH_ENABLED requires a valid definition for VENDOR_PERMANENT_AUTH_HANDLE, see Part2
#  endif
#else
#  if defined(VENDOR_PERMANENT_AUTH_HANDLE)
#    error VENDOR_PERMANENT_AUTH_HANDLE requires VENDOR_PERMANENT_AUTH_ENABLED to be YES
#  endif
#endif

// now check for inconsistent combinations of options
#if USE_KEY_CACHE_FILE && !USE_RSA_KEY_CACHE
#  error cannot use USE_KEY_CACHE_FILE if not using USE_RSA_KEY_CACHE
#endif

#if !DEBUG
#  if USE_KEY_CACHE_FILE || USE_RSA_KEY_CACHE || DRBG_DEBUG_PRINT \
      || CERTIFYX509_DEBUG || USE_DEBUG_RNG || ENABLE_TPM_DEBUG_PRINT
#    error using insecure options not in DEBUG mode.
#  endif
#endif

#if !SIMULATION
#  if USE_KEY_CACHE_FILE
#    error USE_KEY_CACHE_FILE requires SIMULATION
#  endif
#  if RSA_INSTRUMENT
#    error RSA_INSTRUMENT requires SIMULATION
#  endif
#  if USE_DEBUG_RNG
#    error USE_DEBUG_RNG requires SIMULATION
#  endif
#endif

MUST_BE_0_OR_1(SEC_CHANNEL_SUPPORT);
MUST_BE_0_OR_1(CC_PolicyTransportSPDM);
#if SEC_CHANNEL_SUPPORT != CC_PolicyTransportSPDM
#  error SEC_CHANNEL_SUPPORT and CC_PolicyTransportSPDM must have the same value
#endif

#endif  // _VERIFY_CONFIGURATION_H
