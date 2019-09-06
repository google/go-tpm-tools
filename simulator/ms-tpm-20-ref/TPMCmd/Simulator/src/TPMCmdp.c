/* Microsoft Reference Implementation for TPM 2.0
 *
 *  The copyright in this software is being made available under the BSD License,
 *  included below. This software may be subject to other third party and
 *  contributor rights, including patent rights, and no such rights are granted
 *  under this license.
 *
 *  Copyright (c) Microsoft Corporation
 *
 *  All rights reserved.
 *
 *  BSD License
 *
 *  Redistribution and use in source and binary forms, with or without modification,
 *  are permitted provided that the following conditions are met:
 *
 *  Redistributions of source code must retain the above copyright notice, this list
 *  of conditions and the following disclaimer.
 *
 *  Redistributions in binary form must reproduce the above copyright notice, this
 *  list of conditions and the following disclaimer in the documentation and/or
 *  other materials provided with the distribution.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS ""AS IS""
 *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 *  DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
 *  ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 *  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 *  LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
 *  ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 *  SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
//** Description
// This file contains the functions that process the commands received on the
// control port or the command port of the simulator. The control port is used
// to allow simulation of hardware events (such as, _TPM_Hash_Start) to test
// the simulated TPM's reaction to those events. This improves code coverage
// of the testing.

//** Includes and Data Definitions
#include <stdlib.h>
#include <stdio.h>
#include <setjmp.h>
#include "TpmBuildSwitches.h"
#include "BaseTypes.h"

#ifdef _MSC_VER
#   pragma warning(push, 3)
#   include <windows.h>
#   include <winsock.h>
#   pragma warning(pop)
#elif defined(__unix__)
    typedef int SOCKET;
#else
#   error "Unsupported platform."
#endif

#ifndef TRUE
#   define TRUE    1
#endif
#ifndef FALSE
#   define FALSE   0
#endif

#include "Platform_fp.h"
#include "ExecCommand_fp.h"
#include "Manufacture_fp.h"
#include "_TPM_Init_fp.h"
#include "_TPM_Hash_Start_fp.h"
#include "_TPM_Hash_Data_fp.h"
#include "_TPM_Hash_End_fp.h"
#include "TpmFail_fp.h"

#include "TpmTcpProtocol.h"
#include "Simulator_fp.h"

static BOOL     s_isPowerOn = FALSE;

//** Functions

//*** Signal_PowerOn()
// This function processes a power-on indication. Among other things, it
// calls the _TPM_Init() handler.
void
_rpc__Signal_PowerOn(
    BOOL        isReset
    )
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
    s_isPowerOn = TRUE;
}

//*** Signal_Restart()
// This function processes the clock restart indication. All it does is call
// the platform function.
void
_rpc__Signal_Restart(
    void
    )
{
    _plat__TimerRestart();
}

//***Signal_PowerOff()
// This function processes the power off indication. Its primary function is
// to set a flag indicating that the next power on indication should cause
// _TPM_Init() to be called.
void
_rpc__Signal_PowerOff(
    void
    )
{
    if(!s_isPowerOn) return;

    // Pass power off signal to platform
    _plat__Signal_PowerOff();

    s_isPowerOn = FALSE;

    return;
}

//*** _rpc__ForceFailureMode()
// This function is used to debug the Failure Mode logic of the TPM. It will set
// a flag in the TPM code such that the next call to TPM2_SelfTest() will result
// in a failure, putting the TPM into Failure Mode.
void
_rpc__ForceFailureMode(
    void
    )
{
    SetForceFailureMode();
}

//*** _rpc__Signal_PhysicalPresenceOn()
// This function is called to simulate activation of the physical presence "pin".
void
_rpc__Signal_PhysicalPresenceOn(
    void
    )
{
    // If TPM is power off, reject this signal
    if(!s_isPowerOn) return;

    // Pass physical presence on to platform
    _plat__Signal_PhysicalPresenceOn();

    return;
}

//*** _rpc__Signal_PhysicalPresenceOff()
// This function is called to simulate deactivation of the physical presence "pin".
void
_rpc__Signal_PhysicalPresenceOff(
    void
    )
{
    // If TPM is power off, reject this signal
    if(!s_isPowerOn) return;

    // Pass physical presence off to platform
    _plat__Signal_PhysicalPresenceOff();

    return;
}

//*** _rpc__Signal_Hash_Start()
// This function is called to simulate a _TPM_Hash_Start event. It will call
//
void
_rpc__Signal_Hash_Start(
    void
    )
{
    // If TPM is power off, reject this signal
    if(!s_isPowerOn) return;

    // Pass _TPM_Hash_Start signal to TPM
    _TPM_Hash_Start();
    return;
}

//*** _rpc__Signal_Hash_Data()
// This function is called to simulate a _TPM_Hash_Data event.
void
_rpc__Signal_Hash_Data(
    _IN_BUFFER       input
    )
{
    // If TPM is power off, reject this signal
    if(!s_isPowerOn) return;

    // Pass _TPM_Hash_Data signal to TPM
    _TPM_Hash_Data(input.BufferSize, input.Buffer);
    return;
}

//*** _rpc__Signal_HashEnd()
// This function is called to simulate a _TPM_Hash_End event.
void
_rpc__Signal_HashEnd(
    void
    )
{
    // If TPM is power off, reject this signal
    if(!s_isPowerOn) return;

    // Pass _TPM_HashEnd signal to TPM
    _TPM_Hash_End();
    return;
}

//*** _rpc__Send_Command()
// This is the interface to the TPM code.
//  Return Type: void
void
_rpc__Send_Command(
    unsigned char    locality,
    _IN_BUFFER       request,
    _OUT_BUFFER     *response
    )
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
    _plat__RunCommand(request.BufferSize, request.Buffer,
                    &response->BufferSize, &response->Buffer);
    return;
}

//*** _rpc__Signal_CancelOn()
// This function is used to turn on the indication to cancel a command in process.
// An executing command is not interrupted. The command code may periodically check
// this indication to see if it should abort the current command processing and
// returned TPM_RC_CANCELLED.
void
_rpc__Signal_CancelOn(
    void
    )
{
    // If TPM is power off, reject this signal
    if(!s_isPowerOn) return;

    // Set the platform canceling flag.
    _plat__SetCancel();

    return;
}

//*** _rpc__Signal_CancelOff()
// This function is used to turn off the indication to cancel a command in process.
void
_rpc__Signal_CancelOff(
    void
    )
{
    // If TPM is power off, reject this signal
    if(!s_isPowerOn) return;

    // Set the platform canceling flag.
    _plat__ClearCancel();

    return;
}

//*** _rpc__Signal_NvOn()
// In a system where the NV memory used by the TPM is not within the TPM, the
// NV may not always be available. This function turns on the indicator that
// indicates that NV is available.
void
_rpc__Signal_NvOn(
    void
    )
{
    // If TPM is power off, reject this signal
    if(!s_isPowerOn) return;

    _plat__SetNvAvail();
    return;
}

//*** _rpc__Signal_NvOff()
// This function is used to set the indication that NV memory is no
// longer available.
void
_rpc__Signal_NvOff(
    void
    )
{
    // If TPM is power off, reject this signal
    if(!s_isPowerOn) return;

    _plat__ClearNvAvail();
    return;
}

void RsaKeyCacheControl(int state);

//*** _rpc__RsaKeyCacheControl()
// This function is used to enable/disable the use of the RSA key cache during
// simulation.
void
_rpc__RsaKeyCacheControl(
    int              state
    )
{
#if USE_RSA_KEY_CACHE
    RsaKeyCacheControl(state);
#else
    NOT_REFERENCED(state);
#endif
}
