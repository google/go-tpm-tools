//** Includes and locals
#include "Platform.h"
#include <assert.h>
#include <setjmp.h>
#include <stdio.h>

#if LONGJMP_SUPPORTED
// in RunCommand.c
extern jmp_buf s_FailureModeJumpBuffer;
#endif

#if ALLOW_FORCE_FAILURE_MODE
static BOOL s_forceFailureMode;  // flag to force failure mode during test
BOOL        _plat_internal_IsForceFailureMode()
{
    return s_forceFailureMode;
}
LIB_EXPORT void _plat__SetForceFailureMode()
{
    s_forceFailureMode = TRUE;
}
#endif

#if FAIL_TRACE
// The name of the function that triggered failure mode.
static const char* s_failFunctionName;
// The line in the file at which the error was signaled.
static uint32_t s_failLine;
#endif  // FAIL_TRACE

// A numeric indicator of the location that triggered failure mode.
static uint64_t s_failureLocation;
// the reason for the failure.
static uint32_t s_failCode;
static BOOL     s_IsInFailureMode = FALSE;

void            _plat_internal_resetFailureData()
{
#if ALLOW_FORCE_FAILURE_MODE
    s_forceFailureMode = FALSE;
#endif

#if FAIL_TRACE
    // The name of the function that triggered failure mode.
    s_failFunctionName = NULL;
    // The line in the file at which the error was signaled.
    s_failLine = 0;
#endif  // FAIL_TRACE

    // A numeric indicator of the location that triggered failure mode.
    s_failureLocation = 0;
    // the reason for the failure.
    s_failCode        = 0;
    s_IsInFailureMode = FALSE;
}

// Indicates to the TPM Library that a failure has occurred.
// This is REQURIED to return true after any call to _plat__Fail.
// It MAY return true for any other reason the platform deems appropriate.
LIB_EXPORT BOOL _plat__InFailureMode()
{
    return s_IsInFailureMode;
}

//***_plat__Fail()
// A function for the TPM to call the platform to indicate the
// TPM code has detected a failure.
LIB_EXPORT NORETURN_IF_LONGJMP void _plat__Fail(
#if FAIL_TRACE
    const char* function,
    int         line,
#endif
    uint64_t locationCode,
    int      failureCode)
{
#if ALLOW_FORCE_FAILURE_MODE
    // The simulator asserts during unexpected (i.e. un-forced) failure mode
    // to allow debugging.
    if(!_plat_internal_IsForceFailureMode())
    {
        fprintf(stderr, "Unexpected failure mode (code %d) in ", s_failCode);
        uint32_t failureLocation_low = (uint32_t)(_plat__GetFailureLocation());
        uint32_t failureLocation_hi  = (uint32_t)(_plat__GetFailureLocation() >> 32);
        fprintf(
            stderr, "Location: %08x:%08x", failureLocation_hi, failureLocation_low);

#  if FAIL_TRACE
        fprintf(stderr, "function '%s' (line %d)\n", s_failFunctionName, s_failLine);
#  endif  // FAIL_TRACE
        assert(FALSE);
    }
#endif

    // don't update if we are already in failure mode.
    if(!_plat__InFailureMode())
    {
        s_IsInFailureMode = TRUE;
        s_failCode        = failureCode;
        s_failureLocation = locationCode;
#if FAIL_TRACE
        s_failFunctionName = function;
        s_failLine         = line;
#endif
#if ALLOW_FORCE_FAILURE_MODE
        s_forceFailureMode = FALSE;
#endif
    }

#if LONGJMP_SUPPORTED
    longjmp(&s_FailureModeJumpBuffer[0], 1);
#endif
}

LIB_EXPORT UINT32 _plat__GetFailureCode()
{
    return s_failCode;
}

LIB_EXPORT uint64_t _plat__GetFailureLocation()
{
    return s_failureLocation;
}

#if FAIL_TRACE
LIB_EXPORT const char* _plat__GetFailureFunctionName()
{
    return s_failFunctionName;
}

LIB_EXPORT uint32_t _plat__GetFailureLine()
{
    return s_failLine;
}
#endif
