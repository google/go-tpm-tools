// +build cgo

// Package internal provides low-level bindings to the Microsoft TPM2 simulator.
package internal

// // Directories containing .h files in the simulator source
// #cgo CFLAGS: -I ../ms-tpm-20-ref/Samples/Google
// #cgo CFLAGS: -I ../ms-tpm-20-ref/TPMCmd/tpm/include
// #cgo CFLAGS: -I ../ms-tpm-20-ref/TPMCmd/tpm/include/prototypes
// // Allows simulator.c to import files without repeating the source repo path.
// #cgo CFLAGS: -I ../ms-tpm-20-ref/Samples/Google
// #cgo CFLAGS: -I ../ms-tpm-20-ref/TPMCmd/tpm/src
// // Store NVDATA in memory, and we don't care about updates to failedTries.
// #cgo CFLAGS: -DVTPM=NO -DSIMULATION=NO -DUSE_DA_USED=NO
// // Flags from ../ms-tpm-20-ref/TPMCmd/configure.ac
// #cgo CFLAGS: -std=gnu11 -Wall -Wformat-security -fstack-protector-all -fPIC
// // Silence known warnings from the reference code and CGO code.
// #cgo CFLAGS: -Wno-missing-braces -Wno-empty-body -Wno-unused-variable
// // Link against the system OpenSSL
// #cgo CFLAGS: -DDEBUG=YES
// #cgo CFLAGS: -DSIMULATION=NO
// #cgo CFLAGS: -DCOMPILER_CHECKS=DEBUG
// #cgo CFLAGS: -DRUNTIME_SIZE_CHECKS=DEBUG
// #cgo CFLAGS: -DUSE_DA_USED=NO
// #cgo CFLAGS: -DCERTIFYX509_DEBUG=NO
// #cgo CFLAGS: -DECC_NIST_P224=YES
// #cgo CFLAGS: -DECC_NIST_P521=YES
// #cgo CFLAGS: -DALG_SHA512=ALG_YES
// #cgo CFLAGS: -DMAX_CONTEXT_SIZE=1360
// #cgo LDFLAGS: -lcrypto
//
// #include <stdlib.h>
// #include "Platform.h"
// #include "Tpm.h"
import "C"
import (
	"fmt"
	"io"
	"unsafe"
)

// SetSeeds uses the output of r to reset the 3 TPM simulator seeds.
func SetSeeds(r io.Reader) {
	// We need data for 3 seeds of 64 bytes each
	var seeds [64 * 3]byte
	if _, err := io.ReadFull(r, seeds[:]); err != nil {
		panic(fmt.Sprintf("error when reading data for seeds: %v", err))
	}
	C._plat__SetSeeds(C.uint32_t(len(seeds)), (*C.uint8_t)(&seeds[0]))
}

// Reset simulates toggling the power the the TPM. If forceManufacture is true,
// the reset will be a manufacturer reset.
func Reset(forceManufacture bool) {
	C._plat__Reset(C.bool(forceManufacture))
}

// RunCommand passes cmd to the simulator and returns the simulator's response.
func RunCommand(cmd []byte) []byte {
	responseSize := C.uint32_t(C.MAX_RESPONSE_SIZE)
	// _plat__RunCommand takes the response buffer as a uint8_t** instead of as
	// a uint8_t*. As Cgo bans go pointers to go pointers, we must allocate the
	// response buffer with malloc().
	response := C.malloc(C.size_t(responseSize))
	defer C.free(response)
	// Make a copy of the response pointer, so if _plat__RunCommand modifies
	// the pointer, response will still be freed correctly.
	responsePtr := (*C.uint8_t)(response)

	C._plat__RunCommand(C.uint32_t(len(cmd)), (*C.uint8_t)(&cmd[0]),
		&responseSize, &responsePtr)
	return C.GoBytes(unsafe.Pointer(responsePtr), C.int(responseSize))
}
