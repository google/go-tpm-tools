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
//**Introduction
// This module provides the platform specific entry and fail processing. The
// _plat__RunCommand() function is used to call to ExecuteCommand() in the TPM
// code. This function does whatever processing is necessary to set up the
// platform in anticipation of the call to the TPM including settup for error
// processing.
//
// The _plat__Fail() function is called when there is a failure in the TPM. The
// TPM code will have set the flag to indicate that the TPM is in failure mode.
// This call will then recursively call ExecuteCommand in order to build the
// failure mode response. When ExecuteCommand() returns to _plat__Fail(), the
// platform will do some platform specif operation to return to the environment
// in which the TPM is executing. For a simulator, setjmp/longjmp is used. For
// an OS, a system exit to the OS would be appropriate.

#include <setjmp.h>

#include "CompilerDependencies.h"
#include "ExecCommand_fp.h"
#include "Manufacture_fp.h"
#include "Platform.h"
#include "Platform_fp.h"
#include "_TPM_Init_fp.h"

jmp_buf s_jumpBuffer;

void _plat__RunCommand(uint32_t requestSize, unsigned char *request,
                       uint32_t *responseSize, unsigned char **response) {
  setjmp(s_jumpBuffer);
  ExecuteCommand(requestSize, request, responseSize, response);
}

static int s_IsInFailureMode = 0;
static uint64_t s_failureLocation = 0;
static uint32_t s_failCode = 0;
static const char* s_failFunctionName = NULL;
static int s_failLine = 0;

_Noreturn void _plat__Fail(const char *functionName, int lineNumber, uint64_t code, int type) {
  s_IsInFailureMode = 1;
  s_failFunctionName = functionName;
  s_failLine = lineNumber;
  s_failureLocation = code;
  s_failCode = type;
  longjmp(&s_jumpBuffer[0], 1);
}

void _plat__Reset(bool forceManufacture) {
  // We ignore errors, as we don't care if the TPM has been Manufactured before.
  if (forceManufacture) {
    TPM_TearDown();
  }
  TPM_Manufacture(0);
  _plat__TimerReset();
  _TPM_Init();
}

int _plat__IsCanceled(void) { return 0; }
unsigned char _plat__LocalityGet(void) { return 0; }
int _plat__WasPowerLost(void) { return 1; }
int _plat__PhysicalPresenceAsserted(void) { return 1; }

// Stubs for missing platform functions:
#include <tpm_public/TpmAlgorithmDefines.h>
#include <tpm_public/TpmTypes.h>
#include <platform_interface/prototypes/platform_virtual_nv_fp.h>
#include <platform_interface/tpm_to_platform_interface.h>

#include <stdio.h>
#include <stdarg.h>

void _plat_debug_printf(const char *fmt, ...) {
  va_list args;
  va_start(args, fmt);
  vfprintf(stderr, fmt, args);
  va_end(args);
}

int _plat__ACT_GetImplemented(uint32_t act) {
  (void)act;
  return 1;
}

void _plat__ACT_EnableTicks(int enable) {
  (void)enable;
}

void _plat__ACT_Tick(void) {}

int _plat__ACT_Initialize(void) {
  return 0;
}

uint32_t _plat__GetTpmFirmwareVersionHigh(void) { return 0; }
uint32_t _plat__GetTpmFirmwareVersionLow(void) { return 0; }

void _plat__GetPlatformManufactureData(uint8_t *pPlatformPersistentData, uint32_t bufferSize) {
  if (bufferSize != 0) {
    memset((void*)pPlatformPersistentData, 0xFF, bufferSize);
  }
}

void _plat__StartTpmInit(void) {}
void _plat__EndOkTpmInit(void) {}

// Virtual NV stubs
TPM_RC _plat__NvVirtual_PopulateNvIndexInfo(
    TPM_HANDLE      handle,      // IN: handle for the index
    TPMS_NV_PUBLIC* publicArea,  // INOUT: The public area structure to be modified.
    TPM2B_AUTH*     authValue    // INOUT: The auth value structure to be modified.
)
{
    (void)handle;
    (void)publicArea;
    (void)authValue;
    return TPM_RC_NO_RESULT;
}

TPM_RC _plat__NvVirtual_Read(
    NV_Read_In*  in,  // IN: input parameter list
    NV_Read_Out* out  // OUT: output parameter list
)
{
    (void)in;
    (void)out;
    return TPM_RC_NO_RESULT;
}

TPM_RC _plat__NvVirtual_ReadPublic(
    NV_ReadPublic_In*  in,  // IN: input parameter list
    NV_ReadPublic_Out* out  // OUT: output parameter list
)
{
    (void)in;
    (void)out;
    return TPM_RC_NO_RESULT;
}

TPMI_YES_NO _plat__NvVirtual_CapGetIndex(
    TPMI_DH_OBJECT handle,     // IN: start handle
    UINT32         count,      // IN: max number of returned handles
    TPML_HANDLE*   handleList  // OUT: list of handle
)
{
    (void)handle;
    (void)count;
    (void)handleList;
    return NO;
}

BOOL _plat__NvOperationAcceptsVirtualHandles(TPM_CC commandCode)
{
    (void)commandCode;
    return FALSE;
}

BOOL _plat__IsNvVirtualIndex(TPM_HANDLE handle)
{
    (void)handle;
    return FALSE;
}

int _plat__ACT_GetSignaled(uint32_t act) {
  (void)act;
  return 0;
}

int _plat__InFailureMode(void) {
  return s_IsInFailureMode;
}

uint64_t _plat__GetFailureLocation(void) { return s_failureLocation; }
uint32_t _plat__GetFailureCode(void) { return s_failCode; }
const char* _plat__GetFailureFunctionName(void) { return s_failFunctionName; }
uint32_t _plat__GetFailureLine(void) { return s_failLine; }

uint32_t _plat__GetManufacturerCapabilityCode(void) { return 0; }
uint32_t _plat__GetVendorTpmType(void) { return 0; }
uint32_t _plat__GetVendorCapabilityCode(int index) { (void)index; return 0; }

int _plat__GetNvReadyState(void) { return 0; }

int _plat__GetTpmFirmwareSecret(uint16_t secret_buf_size, uint8_t* secret_buf, uint16_t* secret_size) {
  (void)secret_buf_size;
  (void)secret_buf;
  *secret_size = 0;
  return 0;
}

int _plat__GetTpmFirmwareSvnSecret(uint16_t min_svn, uint16_t secret_buf_size, uint8_t* secret_buf, uint16_t* secret_size) {
  (void)min_svn;
  (void)secret_buf_size;
  (void)secret_buf;
  *secret_size = 0;
  return 0;
}

void _plat_GetEnabledSelfTest(
    uint8_t  fullTest,
    uint8_t* pToTestVector,
    size_t   toTestVectorSize
)
{
    (void)fullTest;
    (void)pToTestVector;
    (void)toTestVectorSize;
}

int _plat__ACT_UpdateCounter(uint32_t act, uint32_t newValue) {
  (void)act;
  (void)newValue;
  return 1;
}
void _plat__ACT_SetSignaled(uint32_t act, int signaled) {
  (void)act;
  (void)signaled;
}
uint32_t _plat__ACT_GetRemaining(uint32_t act) {
  (void)act;
  return 0;
}

uint16_t _plat__GetTpmFirmwareSvn(void) { return 0; }
uint16_t _plat__GetTpmFirmwareMaxSvn(void) { return 0; }

void _plat__TearDown(void) {}

void _plat_debug_print(const char* str) {
  fputs(str, stderr);
}

void _plat_GetSpecCapabilityValue(SPEC_CAPABILITY_VALUE* returnData) {
    returnData->tpmSpecLevel      = 0;
    returnData->tpmSpecVersion    = 184;
    returnData->tpmSpecYear       = 2025;
    returnData->tpmSpecDayOfYear  = 79;
    returnData->platformFamily    = 1;
    returnData->platfromLevel     = 0;
    returnData->platformRevision  = 0x105;
    returnData->platformYear      = 0;
    returnData->platformDayOfYear = 0;
}
