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
//** Description
//
//    This file contains the NV read and write access methods.  This
//    implementation uses RAM/file and does not manage the RAM/file as NV
//    blocks. The implementation may become more sophisticated over time.
//

#include <assert.h>
#include <string.h>

#include "PlatformData.h"
#include "Platform_fp.h"

unsigned char s_NV[NV_MEMORY_SIZE];

int _plat__NvMemoryRead(unsigned int start, unsigned int size, void *data) {
  assert(start + size <= NV_MEMORY_SIZE);
  memcpy(data, &s_NV[start], size);
  return 1;
}

int _plat__NvGetChangedStatus(unsigned int start, unsigned int size, void *data) {
  return (memcmp(&s_NV[start], data, size) != 0);
}

int _plat__NvMemoryWrite(unsigned int start, unsigned int size, void *data) {
  if (start + size <= NV_MEMORY_SIZE) {
    memcpy(&s_NV[start], data, size);
    return 1;
  }
  return 0;
}

int _plat__NvMemoryClear(unsigned int start, unsigned int size) {
  assert(start + size <= NV_MEMORY_SIZE);
  // In this implementation, assume that the erase value for NV is all 1s
  memset(&s_NV[start], 0xff, size);
  return 1;
}

int _plat__NvMemoryMove(unsigned int sourceOffset, unsigned int destOffset,
                         unsigned int size) {
  assert(sourceOffset + size <= NV_MEMORY_SIZE);
  assert(destOffset + size <= NV_MEMORY_SIZE);
  memmove(&s_NV[destOffset], &s_NV[sourceOffset], size);
  return 1;
}

int _plat__NVEnable(void *platParameter, size_t size) {
  (void)platParameter;
  (void)size;
  return 0;
}

int _plat__NvCommit(void) { return 0; }
