// Package main provides an offline utility to calculate the expected MRTD
// (Measurement of Resources at Td Launch) from a TDX firmware file (OVMF).
package main

import (
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"

	"github.com/google/gce-tcb-verifier/tdx"
)

// cleanTdx takes the raw firmware bytes, simulates the hardware launch,
// and returns the expected 48-byte MRTD as a hex string.
func cleanTdx(fw []byte) string {
	meas, err := tdx.MRTD(tdx.LaunchOptionsDefault(""), fw)
	if err != nil {
		fmt.Printf("Failed to compute MRTD: %v\n", err)
		os.Exit(1)
	}
	return hex.EncodeToString(meas[:])
}

func main() {
	filePath := "OVMF.inteltdx.fd"
	if len(os.Args) > 1 {
		filePath = os.Args[1]
	}

	fmt.Printf("Reading file: %s\n", filepath.Base(filePath))

	fw, err := os.ReadFile(filePath)
	if err != nil {
		fmt.Printf("Failed to read file %s: %v\n", filePath, err)
		os.Exit(1)
	}

	mrtdHex := cleanTdx(fw)

	fmt.Printf("MRTD: %s\n", mrtdHex)
}
