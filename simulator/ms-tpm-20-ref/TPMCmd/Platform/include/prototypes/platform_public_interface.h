
// This file contains the interface into the platform layer from external callers.
// External callers are expected to be implementation specific, and may be a simulator
// or some other implementation

#ifndef _PLATFORM_PUBLIC_INTERFACE_H_
#define _PLATFORM_PUBLIC_INTERFACE_H_

#include <stddef.h>

#if ALLOW_FORCE_FAILURE_MODE
// From Failure.c
// allow simulator to force the TPM into failure mode.
LIB_EXPORT void _plat__SetForceFailureMode();
#endif

//** From Cancel.c
// Set cancel flag.
LIB_EXPORT void _plat__SetCancel(void);

//***_plat__ClearCancel()
// Clear cancel flag
LIB_EXPORT void _plat__ClearCancel(void);

//** From Clock.c

//***_plat__TimerReset()
// This function sets current system clock time as t0 for counting TPM time.
// This function is called at a power on event to reset the clock. When the clock
// is reset, the indication that the clock was stopped is also set.
LIB_EXPORT void _plat__TimerReset(void);

//*** _plat__TimerRestart()
// This function should be called in order to simulate the restart of the timer
// should it be stopped while power is still applied.
LIB_EXPORT void _plat__TimerRestart(void);

//*** _plat__RealTime()
// This is another, probably futile, attempt to define a portable function
// that will return a 64-bit clock value that has mSec resolution.
LIB_EXPORT uint64_t _plat__RealTime(void);

//** From LocalityPlat.c

//***_plat__LocalitySet()
// Set the most recent command locality in locality value form
LIB_EXPORT void _plat__LocalitySet(unsigned char locality);

//** From NVMem.c

//*** _plat__NvErrors()
// This function is used by the simulator to set the error flags in the NV
// subsystem to simulate an error in the NV loading process
LIB_EXPORT void _plat__NvErrors(int recoverable, int unrecoverable);

//***_plat__NVDisable()
// Disable NV memory
LIB_EXPORT void _plat__NVDisable(
    void*  platParameter,  // platform specific parameter
    size_t paramSize       // size of parameter. If size == 0, then
                           // parameter is a sizeof(void*) scalar and should
                           // be cast to an integer (intptr_t), not dereferenced.
);

//***_plat__SetNvAvail()
// Set the current NV state to available.  This function is for testing purpose
// only.  It is not part of the platform NV logic
LIB_EXPORT void _plat__SetNvAvail(void);

//***_plat__ClearNvAvail()
// Set the current NV state to unavailable.  This function is for testing purpose
// only.  It is not part of the platform NV logic
LIB_EXPORT void _plat__ClearNvAvail(void);

//*** _plat__NVNeedsManufacture()
// This function is used by the simulator to determine when the TPM's NV state
// needs to be manufactured.
LIB_EXPORT int _plat__NVNeedsManufacture(void);

//** From PlatformACT.c

//*** _plat__ACT_GetPending()
LIB_EXPORT int _plat__ACT_GetPending(uint32_t act  //IN: number of ACT to check
);

//*** _plat__ACT_Tick()
// This processes the once-per-second clock tick from the hardware. This is set up
// for the simulator to use the control interface to send ticks to the TPM. These
// ticks do not have to be on a per second basis. They can be as slow or as fast as
// desired so that the simulation can be tested.
LIB_EXPORT void _plat__ACT_Tick(void);

//** From PowerPlat.c

//***_plat__Signal_PowerOn()
// Signal platform power on
LIB_EXPORT int _plat__Signal_PowerOn(void);

//*** _plat_Signal_Reset()
// This a TPM reset without a power loss.
LIB_EXPORT int _plat__Signal_Reset(void);

//***_plat__Signal_PowerOff()
// Signal platform power off
LIB_EXPORT void _plat__Signal_PowerOff(void);

//** From PPPlat.c

//***_plat__Signal_PhysicalPresenceOn()
// Signal physical presence on
LIB_EXPORT void _plat__Signal_PhysicalPresenceOn(void);

//***_plat__Signal_PhysicalPresenceOff()
// Signal physical presence off
LIB_EXPORT void _plat__Signal_PhysicalPresenceOff(void);

//*** _plat__SetTpmFirmwareHash()
// Called by the simulator to set the TPM Firmware hash used for
// firmware-bound hierarchies. Not a cryptographically-strong hash.
#if SIMULATION
LIB_EXPORT void _plat__SetTpmFirmwareHash(uint32_t hash);
#endif

//*** _plat__SetTpmFirmwareSvn()
// Called by the simulator to set the TPM Firmware SVN reported by
// getCapability.
#if SIMULATION
LIB_EXPORT void _plat__SetTpmFirmwareSvn(uint16_t svn);
#endif

//** From RunCommand.c

//***_plat__RunCommand()
// This version of RunCommand will set up a jum_buf and call ExecuteCommand(). If
// the command executes without failing, it will return and RunCommand will return.
// If there is a failure in the command, then _plat__Fail() is called and it will
// longjump back to RunCommand which will call ExecuteCommand again. However, this
// time, the TPM will be in failure mode so ExecuteCommand will simply build
// a failure response and return.
LIB_EXPORT void _plat__RunCommand(
    uint32_t        requestSize,   // IN: command buffer size
    unsigned char*  request,       // IN: command buffer
    uint32_t*       responseSize,  // IN/OUT: response buffer size
    unsigned char** response       // IN/OUT: response buffer
);

#endif  // _PLATFORM_PUBLIC_INTERFACE_H_