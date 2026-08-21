package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func createSampleSigstruct() []byte {
	buffer := make([]byte, SigstructSize)
	copy(buffer[header1Offset:header1Offset+header1Length], header1Magic)
	binary.LittleEndian.PutUint32(buffer[vendorOffset:vendorOffset+4], 0x8086)
	binary.LittleEndian.PutUint32(buffer[dateOffset:dateOffset+4], 20260818)
	copy(buffer[header2Offset:header2Offset+header2Length], header2Magic)

	for i := rsaModulusOffset; i < rsaModulusOffset+rsaModulusLength; i++ {
		buffer[i] = byte(i % 256)
	}

	binary.LittleEndian.PutUint32(buffer[miscSelectOffset:miscSelectOffset+4], 0x00000001)
	binary.LittleEndian.PutUint32(buffer[miscMaskOffset:miscMaskOffset+4], 0xFFFFFFFF)

	for i := 0; i < mrEnclaveLength; i++ {
		buffer[mrEnclaveOffset+i] = byte(i + 1)
	}

	binary.LittleEndian.PutUint16(buffer[isvProdIDOffset:isvProdIDOffset+2], 42)
	binary.LittleEndian.PutUint16(buffer[isvSVNOffset:isvSVNOffset+2], 3)

	return buffer
}

func TestParseSigstruct(t *testing.T) {
	sampleSigstruct := createSampleSigstruct()
	info, err := ParseSigstruct(sampleSigstruct)
	if err != nil {
		t.Fatalf("ParseSigstruct() failed: %v", err)
	}

	if got, want := info.HeaderVendor, uint32(0x8086); got != want {
		t.Errorf("HeaderVendor = 0x%x, want 0x%x", got, want)
	}
	if got, want := info.ISVProdID, uint16(42); got != want {
		t.Errorf("ISVProdID = %d, want %d", got, want)
	}
	if got, want := info.ISVSVN, uint16(3); got != want {
		t.Errorf("ISVSVN = %d, want %d", got, want)
	}

	wantMREnclave := hex.EncodeToString(sampleSigstruct[mrEnclaveOffset : mrEnclaveOffset+mrEnclaveLength])
	if got := info.MREnclave; got != wantMREnclave {
		t.Errorf("MREnclave = %q, want %q", got, wantMREnclave)
	}

	wantMRSigner := sha256.Sum256(sampleSigstruct[rsaModulusOffset : rsaModulusOffset+rsaModulusLength])
	if got := info.MRSigner; got != hex.EncodeToString(wantMRSigner[:]) {
		t.Errorf("MRSigner = %q, want %q", got, hex.EncodeToString(wantMRSigner[:]))
	}
}

func TestParseSigstructInvalid(t *testing.T) {
	truncatedData := make([]byte, 100)
	if _, err := ParseSigstruct(truncatedData); err == nil {
		t.Error("ParseSigstruct() on truncated data succeeded, want error")
	}
}

func TestExtractSigstructEmbedded(t *testing.T) {
	tempDirectory := t.TempDir()
	sampleSigstruct := createSampleSigstruct()

	wrappedPayload := append([]byte("SIMULATED_ELF_HEADER_PREFIX"), sampleSigstruct...)
	wrappedPayload = append(wrappedPayload, []byte("TRAILING_ELF_SECTION_DATA")...)

	filePath := filepath.Join(tempDirectory, "test.signed.so")
	if err := os.WriteFile(filePath, wrappedPayload, 0o644); err != nil {
		t.Fatalf("WriteFile(%q) failed: %v", filePath, err)
	}

	extractedSigstruct, err := ExtractSigstruct(filePath)
	if err != nil {
		t.Fatalf("ExtractSigstruct(%q) failed: %v", filePath, err)
	}

	if !bytes.Equal(extractedSigstruct, sampleSigstruct) {
		t.Errorf("extracted bytes = %x, want %x", extractedSigstruct, sampleSigstruct)
	}
}
