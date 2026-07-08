//** Description
// This file contains the functions that process the commands received on the
// control port or the command port of the simulator. The control port is used
// to allow simulation of hardware events (such as, _TPM_Hash_Start) to test
// the simulated TPM's reaction to those events. This improves code coverage
// of the testing.

//** Includes and Data Definitions
#include "simulatorPrivate.h"

static bool s_isPowerOn = false;

//** Functions

//*** Signal_PowerOn()
// This function processes a power-on indication. Among other things, it
// calls the _TPM_Init() handler.
void _rpc__Signal_PowerOn(bool isReset)
{
    // if power is on and this is not a call to do TPM reset then return
    if(s_isPowerOn && !isReset)
        return;
    // If this is a reset but power is not on, then return
    if(isReset && !s_isPowerOn)
        return;
    // Unless this is just a reset, pass power on signal to platform
    if(!isReset)
        _plat__Signal_PowerOn();
    // Power on and reset both lead to _TPM_Init()
    _plat__Signal_Reset();

    // Set state as power on
    s_isPowerOn = true;
}

//*** Signal_Restart()
// This function processes the clock restart indication. All it does is call
// the platform function.
void _rpc__Signal_Restart(void)
{
    _plat__TimerRestart();
}

//***Signal_PowerOff()
// This function processes the power off indication. Its primary function is
// to set a flag indicating that the next power on indication should cause
// _TPM_Init() to be called.
void _rpc__Signal_PowerOff(void)
{
    if(s_isPowerOn)
        // Pass power off signal to platform
        _plat__Signal_PowerOff();
    // This could be redundant, but...
    s_isPowerOn = false;

    return;
}

//*** _rpc__ForceFailureMode()
// This function is used to debug the Failure Mode logic of the TPM. It will set
// a flag in the TPM code such that the next call to TPM2_SelfTest() will result
// in a failure, putting the TPM into Failure Mode.
void _rpc__ForceFailureMode(void)
{
#if SIMULATION
    _plat__SetForceFailureMode();
#endif
    return;
}

//*** _rpc__Signal_PhysicalPresenceOn()
// This function is called to simulate activation of the physical presence "pin".
void _rpc__Signal_PhysicalPresenceOn(void)
{
    // If TPM power is on...
    if(s_isPowerOn)
        // ... pass physical presence on to platform
        _plat__Signal_PhysicalPresenceOn();
    return;
}

//*** _rpc__Signal_PhysicalPresenceOff()
// This function is called to simulate deactivation of the physical presence "pin".
void _rpc__Signal_PhysicalPresenceOff(void)
{
    // If TPM is power on...
    if(s_isPowerOn)
        // ... pass physical presence off to platform
        _plat__Signal_PhysicalPresenceOff();
    return;
}

//*** _rpc__Signal_Hash_Start()
// This function is called to simulate a _TPM_Hash_Start event. It will call
//
void _rpc__Signal_Hash_Start(void)
{
    // If TPM power is on...
    if(s_isPowerOn)
        // ... pass _TPM_Hash_Start signal to TPM
        _TPM_Hash_Start();
    return;
}

//*** _rpc__Signal_Hash_Data()
// This function is called to simulate a _TPM_Hash_Data event.
void _rpc__Signal_Hash_Data(_IN_BUFFER input)
{
    // If TPM power is on...
    if(s_isPowerOn)
        // ... pass _TPM_Hash_Data signal to TPM
        _TPM_Hash_Data(input.BufferSize, input.Buffer);
    return;
}

//*** _rpc__Signal_HashEnd()
// This function is called to simulate a _TPM_Hash_End event.
void _rpc__Signal_HashEnd(void)
{
    // If TPM power is on...
    if(s_isPowerOn)
        // ... pass _TPM_HashEnd signal to TPM
        _TPM_Hash_End();
    return;
}

//*** _rpc__Send_Command()
// This is the interface to the TPM code.
//  Return Type: void
void _rpc__Send_Command(
    unsigned char locality, _IN_BUFFER request, _OUT_BUFFER* response)
{
    // If TPM is power off, reject any commands.
    if(!s_isPowerOn)
    {
        response->BufferSize = 0;
        return;
    }
    // Set the locality of the command so that it doesn't change during the command
    _plat__LocalitySet(locality);
    // Do implementation-specific command dispatch
    _plat__RunCommand(
        request.BufferSize, request.Buffer, &response->BufferSize, &response->Buffer);
    return;
}

//*** _rpc__Signal_CancelOn()
// This function is used to turn on the indication to cancel a command in process.
// An executing command is not interrupted. The command code may periodically check
// this indication to see if it should abort the current command processing and
// returned TPM_RC_CANCELLED.
void _rpc__Signal_CancelOn(void)
{
    // If TPM power is on...
    if(s_isPowerOn)
        // ... set the platform canceling flag.
        _plat__SetCancel();
    return;
}

//*** _rpc__Signal_CancelOff()
// This function is used to turn off the indication to cancel a command in process.
void _rpc__Signal_CancelOff(void)
{
    // If TPM power is on...
    if(s_isPowerOn)
        // ... set the platform canceling flag.
        _plat__ClearCancel();
    return;
}

//*** _rpc__Signal_NvOn()
// In a system where the NV memory used by the TPM is not within the TPM, the
// NV may not always be available. This function turns on the indicator that
// indicates that NV is available.
void _rpc__Signal_NvOn(void)
{
    // If TPM power is on...
    if(s_isPowerOn)
        // ... make the NV available
        _plat__SetNvAvail();
    return;
}

//*** _rpc__Signal_NvOff()
// This function is used to set the indication that NV memory is no
// longer available.
void _rpc__Signal_NvOff(void)
{
    // If TPM power is on...
    if(s_isPowerOn)
        // ... make NV not available
        _plat__ClearNvAvail();
    return;
}

void RsaKeyCacheControl(int state);

//*** _rpc__RsaKeyCacheControl()
// This function is used to enable/disable the use of the RSA key cache during
// simulation.
void _rpc__RsaKeyCacheControl(int state)
{
#if USE_RSA_KEY_CACHE
    RsaKeyCacheControl(state);
#else
    NOT_REFERENCED(state);
#endif
    return;
}

//*** _rpc__ACT_GetSignaled()
// This function is used to count the ACT second tick.
bool _rpc__ACT_GetSignaled(uint32_t actHandle)
{
#if ACT_SUPPORT
    // If TPM power is on...
    if(s_isPowerOn)
        // ... query the platform
        return _plat__ACT_GetSignaled(actHandle - TPM_RH_ACT_0);
#else   // ACT_SUPPORT
    NOT_REFERENCED(actHandle);
#endif  // ACT_SUPPORT
    return false;
}

//*** _rpc__SetTpmFirmwareHash()
// This function is used to modify the firmware's hash during simulation.
void _rpc__SetTpmFirmwareHash(uint32_t hash)
{
#if SIMULATION
    _plat__SetTpmFirmwareHash(hash);
#endif
}

//*** _rpc__SetTpmFirmwareSvn()
// This function is used to modify the firmware's SVN during simulation.
void _rpc__SetTpmFirmwareSvn(uint16_t svn)
{
#if SIMULATION
    _plat__SetTpmFirmwareSvn(svn);
#endif
}