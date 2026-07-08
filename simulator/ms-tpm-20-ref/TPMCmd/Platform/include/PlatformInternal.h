// Private platform internal functions

#if ALLOW_FORCE_FAILURE_MODE
// From Failure.c
// allow simulator to force the TPM into failure mode.
BOOL _plat_internal_IsForceFailureMode();
#endif

void _plat_internal_resetFailureData(void);
