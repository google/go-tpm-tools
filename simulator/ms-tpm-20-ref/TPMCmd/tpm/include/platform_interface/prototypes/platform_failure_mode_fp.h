// Failure mode platform functions
// The platform is responsible for tracking and handling failure
// mode, and for returning the data for GetTestResult when in
// failure mode.  This allows the Core TPM library to implement
// the basic command handling while making minimal assumptions
// about the data the platform will track, and also, critically,
// allows the platform to put the TPM into failure mode due to
// it's own internal failures without forcing a dependency on the
// tpm library's internal error handling macros and functions
// throughout unrelated platform code

#ifndef _PLATFORM_FAILURE_MODE_FP_H_
#define _PLATFORM_FAILURE_MODE_FP_H_

//***_plat__Fail()
// A function for the TPM to call the platform to indicate the
// TPM code has detected a failure.
LIB_EXPORT NORETURN_IF_LONGJMP void _plat__Fail(
#if FAIL_TRACE
    const char* function,
    int         line,
#endif
    uint64_t locationCode,
    int      failureCode);

// Indicates to the TPM Library that a failure has occurred.
// This is REQUIRED to return true after any call to _plat__Fail.
// It MAY return true for any other reason the platform deems appropriate.
LIB_EXPORT BOOL _plat__InFailureMode(void);

// The failure reason.  Values are vendor defined by the TpmConfiguration
// project in the TpmProfile_ErrorCodes.h header
LIB_EXPORT UINT32 _plat__GetFailureCode(void);

// A vendor defined 64-bit code indicating where the failure occured.
// this is defined by the return of the CODELOCATION() macro which may be
// defined in TpmConfiguration.  If not defined, returns zero.
LIB_EXPORT uint64_t _plat__GetFailureLocation(void);

// Provides human readable failure information.  Not necessarily suitable for production.
#if FAIL_TRACE
LIB_EXPORT const char* _plat__GetFailureFunctionName(void);
LIB_EXPORT uint32_t    _plat__GetFailureLine(void);
#endif

#endif  // _PLATFORM_FAILURE_MODE_FP_H_