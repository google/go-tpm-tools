/* Microsoft Reference Implementation for TPM 2.0
 *
 *  The copyright in this software is being made available under the BSD
 * License, included below. This software may be subject to other third party
 * and contributor rights, including patent rights, and no such rights are
 * granted under this license.
 *
 *  Copyright (c) Microsoft Corporation
 *
 *  All rights reserved.
 *
 *  BSD License
 *
 *  Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *  Redistributions of source code must retain the above copyright notice, this
 * list of conditions and the following disclaimer.
 *
 *  Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS ""AS
 * IS"" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
// Platform functions used by libtpm

#ifndef _PLATFORM_FP_H_
#define _PLATFORM_FP_H_

#include <stdbool.h>
#include <stdint.h>

//***_plat__IsCanceled()
// We opt to not support cancellation, so always return false.
// Return values:
//  true(1)         if cancel flag is set
//  false(0)        if cancel flag is not set
int _plat__IsCanceled(void);

//***_plat__TimerReset()
// This function sets current system clock time as t0 for counting TPM time.
// This function is called at a power on event to reset the clock. When the
// clock is reset, the indication that the clock was stopped is also set.
void _plat__TimerReset();

//***_plat__TimerRead()
// This function provides access to the tick timer of the platform. The TPM code
// uses this value to drive the TPM Clock.
//
// The tick timer is supposed to run when power is applied to the device. This
// timer should not be reset by time events including _TPM_Init. It should only
// be reset when TPM power is re-applied.
//
// If the TPM is run in a protected environment, that environment may provide
// the tick time to the TPM as long as the time provided by the environment is
// not allowed to go backwards. If the time provided by the system can go
// backwards during a power discontinuity, then the _plat__Signal_PowerOn should
// call _plat__TimerReset().
uint64_t _plat__TimerRead();

//*** _plat__TimerWasReset()
// This function is used to interrogate the flag indicating if the tick timer
// has been reset.
//
// If the resetFlag parameter is SET, then the flag will be CLEAR before the
// function returns.
int _plat__TimerWasReset(void);

//*** _plat__TimerWasStopped()
// As we have CLOCK_STOPS=NO, we will only stop our timer on resets.
int _plat__TimerWasStopped(void);

// Note: _plat__ClockRateAdjust is declared in tpm_to_platform_interface.h

//*** _plat__GetEntropy()
// This function is used to get available hardware entropy. In a hardware
// implementation of this function, there would be no call to the system
// to get entropy.
// Return values:
//  < 0        hardware failure of the entropy generator, this is sticky
// >= 0        the returned amount of entropy (bytes)
int32_t _plat__GetEntropy(uint8_t *entropy,  // output buffer
                          uint32_t amount    // amount requested
);

//***_plat__LocalityGet()
// We do not support non-zero localities, so just always return 0.
unsigned char _plat__LocalityGet(void);

//***_plat__NVEnable()
// As we just hold the NV data in memory, always return success.
// Return values:
//    0        if success
//  > 0        if receive recoverable error
//  < 0        if unrecoverable error
int _plat__NVEnable(void *platParameter, size_t size);

//***_plat__IsNvAvailable()
// Our NV Data is always available and has no write limits.
// Return values:
//    0        NV is available
//    1        NV is not available due to write failure
//    2        NV is not available due to rate limit
static inline int _plat__IsNvAvailable() { return 0; }

//***_plat__NvMemoryRead()
int _plat__NvMemoryRead(unsigned int startOffset,  // IN: read start
                        unsigned int size,         // IN: size of bytes to read
                        void *data                 // OUT: data buffer
);

int _plat__NvGetChangedStatus(unsigned int startOffset,  // IN: read start
                              unsigned int size,         // IN: size of bytes to read
                              void *data                 // IN: data buffer
);
// NOTE: A useful optimization would be for this code to compare the current
// contents of NV with the local copy and note the blocks that have changed.
// Then only write those blocks when _plat__NvCommit() is called.
int _plat__NvMemoryWrite(unsigned int startOffset,  // IN: write start
                         unsigned int size,  // IN: size of bytes to write
                         void *data          // OUT: data buffer
);

//***_plat__NvMemoryClear()
// Function is used to set a range of NV memory bytes to an implementation-
// dependent value. The value represents the erase state of the memory.
int _plat__NvMemoryClear(unsigned int start,  // IN: clear start
                         unsigned int size    // IN: number of bytes to clear
);

//***_plat__NvMemoryMove()
// Function: Move a chunk of NV memory from source to destination
//      This function should ensure that if there overlap, the original data is
//      copied before it is written
int _plat__NvMemoryMove(unsigned int sourceOffset,  // IN: source offset
                        unsigned int destOffset,    // IN: destination offset
                        unsigned int size  // IN: size of data being moved
);

//***_plat__NvCommit()
// Our NV Data is just in memory, so "committing" it is a no-op.
// Return values:
//    0        NV write success
// != 0        NV write fail
int _plat__NvCommit(void);

//*** _plat__WasPowerLost()
// Test whether power was lost before a _TPM_Init. As we use in-memory NV Data,
// there's no reason to to not do the power-loss activities on every _TPM_Init.
// Return values:
//  true(1)         power was lost
//  false(0)        power was not lost
int _plat__WasPowerLost(void);

//** From PPPlat.c

//***_plat__PhysicalPresenceAsserted()
// Our vTPM has no way to assert physical presence, so we always return true.
// Return values:
//  true(1)         if physical presence is signaled
//  false(0)        if physical presence is not signaled
int _plat__PhysicalPresenceAsserted(void);

//***_plat__Fail()
// This is the platform depended failure exit for the TPM.
_Noreturn void _plat__Fail(const char *functionName, int lineNumber, uint64_t code, int type);

#endif  // _PLATFORM_FP_H_
