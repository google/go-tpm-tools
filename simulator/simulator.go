/*
 * Copyright 2018 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */

// Package simulator provides a go-tpm interface to the IBM TPM2 simulator.
package simulator

// CFLAGS and LDFLAGS modified from upstream Makefile to get the library
// building with cgo: -Wno-unused-variable is to work around a cgo bug and
// -Wno-strict-aliasing is due to unsafe pointer math in the TPM simulator.

// #cgo CFLAGS: -DTPM_POSIX -DVTPM=NO -DUSE_BIT_FIELD_STRUCTURES=NO -DUSE_DA_USED=NO -Wall -Wno-expansion-to-defined -Wno-self-assign -Wno-unused-variable -Wno-strict-aliasing -Wnested-externs -Wsign-compare
// #cgo LDFLAGS: -lcrypto -lpthread -lrt
//
// #include <stdlib.h>
// #include "Tpm.h"
//
// void sync_seeds() {
//     NV_SYNC_PERSISTENT(EPSeed);
//     NV_SYNC_PERSISTENT(SPSeed);
//     NV_SYNC_PERSISTENT(PPSeed);
// }
//
// // This terrible (and quite unsafe) pointer magic is mandated by the TCG TPM2
// // Specification, Part 4 (code), section 9.17.4.2.
// const char* fail_function_name() {
// 	   return (const char*)(uintptr_t)s_failFunction;
// }
import "C"
import (
	"bytes"
	"errors"
	"fmt"
	"math/rand"
	"sync"
	"unsafe"

	"github.com/google/go-tpm/tpm2"
)

// Simulator represents a go-tpm compatible interface to the IBM TPM2 simulator.
// Similar to the file-based (for linux) or syscall-based (for Windows) TPM
// handles, no synchronization is provided; the same simulator handle should not
// be used from multiple threads.
type Simulator struct {
	buf bytes.Buffer
}

// ErrSimulatorInUse indicates another open Simulator already exists.
var ErrSimulatorInUse = errors.New("simulator is being used by another caller")

// The simulator is a global resource, so we use the variables below to make
// sure we only ever have one open reference to the Simulator at a time.
var (
	lock  sync.Mutex
	inUse bool
)

// Get the pointer to an initialized, powered on, and started simulator. As only
// one simulator may be running at a time, a second call to Get() will return
// ErrSimulatorInUse until the first Simulator is Closed.
func Get() (*Simulator, error) {
	lock.Lock()
	defer lock.Unlock()
	if inUse {
		return nil, ErrSimulatorInUse
	}

	simulator := &Simulator{}
	if err := simulator.on(true); err != nil {
		return nil, err
	}
	inUse = true
	return simulator, nil
}

// GetWithFixedSeedInsecure behaves like Get() expect that all of the internal
// hierarchy seeds are derived from the input seed. Note that this function
// compromises the security of the keys/seeds and should only be used for tests.
func GetWithFixedSeedInsecure(seed int64) (*Simulator, error) {
	r := rand.New(rand.NewSource(seed))
	s, err := Get()
	if err != nil {
		return nil, err
	}

	// The first two bytes of the seed encode the size (so we don't overwrite)
	r.Read(C.gp.EPSeed[2:])
	r.Read(C.gp.SPSeed[2:])
	r.Read(C.gp.PPSeed[2:])
	C.sync_seeds()
	return s, nil
}

// Reset the TPM as if the host computer had rebooted.
func (s *Simulator) Reset() error {
	if err := s.off(); err != nil {
		return err
	}
	return s.on(false)
}

// ManufactureReset behaves like Reset() except that the TPM is complete wiped.
// All data (NVData, Hierarchy seeds, etc...) is cleared or reset.
func (s *Simulator) ManufactureReset() error {
	if err := s.off(); err != nil {
		return err
	}
	return s.on(true)
}

// Write executes the command specified by commandBuffer. The command response
// can be retrieved with a subsequent call to Read().
func (s *Simulator) Write(commandBuffer []byte) (int, error) {
	resp, err := runCommand(commandBuffer)
	if err != nil {
		return 0, err
	}
	return s.buf.Write(resp)
}

// Read gets the response of a command previously issued by calling Write().
func (s *Simulator) Read(responseBuffer []byte) (int, error) {
	return s.buf.Read(responseBuffer)
}

// Close cleans up and stops the simulator, Close() should always be called when
// the Simulator is no longer needed, freeing up other callers to use Get().
func (s *Simulator) Close() error {
	lock.Lock()
	defer lock.Unlock()
	inUse = false
	return s.off()
}

func (s *Simulator) on(manufactureReset bool) error {
	// Setup the simulator to receive commands
	C._plat__Signal_PowerOn()
	C._plat__Signal_Reset()
	C._plat__SetNvAvail()
	C._plat__Signal_PhysicalPresenceOn()
	if manufactureReset {
		if rc := C.TPM_Manufacture(1); rc != C.TPM_RC_SUCCESS {
			return fmt.Errorf("manufacture reset failed: code %x", rc)
		}
	}
	// TPM2_Setup must be the first command the TPM receives
	if err := tpm2.Startup(s, tpm2.StartupClear); err != nil {
		return fmt.Errorf("startup: %v", err)
	}
	return nil
}

func (s *Simulator) off() error {
	// TPM2_Shutdown must be the first command the TPM receives. We call
	// Shutdown with StartupClear to simulate a full reboot.
	if err := tpm2.Shutdown(s, tpm2.StartupClear); err != nil {
		return fmt.Errorf("shutdown: %v", err)
	}
	C._plat__Signal_PhysicalPresenceOff()
	C._plat__ClearNvAvail()
	C._plat__Signal_PowerOff()
	return nil
}

func runCommand(cmd []byte) ([]byte, error) {
	responseSize := C.uint32_t(C.MAX_RESPONSE_SIZE)
	// _plat__RunCommand takes the response buffer as a uint8_t** instead of as
	// a uint8_t*. As Cgo bans go pointers to go pointers, we must allocate the
	// response buffer with malloc().
	response := C.malloc(C.size_t(responseSize))
	defer C.free(response)
	// Make a copy of the response pointer, so we can be sure _plat__RunCommand
	// doesn't modify the pointer (it _is_ expected to modify the buffer).
	responsePtr := (*C.uint8_t)(response)

	C._plat__RunCommand(C.uint32_t(len(cmd)), (*C.uint8_t)(&cmd[0]),
		&responseSize, &responsePtr)
	// As long as NO_FAIL_TRACE is not defined, debug error information is
	// written to certain global variables on internal failure.
	if C.g_inFailureMode == C.TRUE {
		if functionName := C.fail_function_name(); functionName != nil {
			return nil, fmt.Errorf("internal failure: %s, line %d, code %d",
				C.GoString(functionName), C.s_failLine, C.s_failCode)
		}
		return nil, errors.New("internal failure (NO_FAIL_TRACE)")
	}
	if response != unsafe.Pointer(responsePtr) {
		panic("Response pointer shouldn't be modified on success")
	}
	return C.GoBytes(response, C.int(responseSize)), nil
}
