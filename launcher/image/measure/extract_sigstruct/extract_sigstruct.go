// Package main provides a command-line tool to extract the 1808-byte Intel SGX
// Enclave Signature Structure (SIGSTRUCT / enclave_css_t) from a signed enclave
// ELF shared object (such as libsgx_tdqe.signed.so.1) or a raw sigstruct payload.
package main

import (
	"bytes"
	"crypto/sha256"
	"debug/elf"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
)

const (
	SigstructSize = 1808

	header1Offset = 0
	header1Length = 12

	vendorOffset = 16
	dateOffset   = 20

	header2Offset = 24
	header2Length = 16

	rsaModulusOffset = 128
	rsaModulusLength = 384

	miscSelectOffset = 900
	miscMaskOffset   = 904

	isvFamilyIDOffset = 912
	isvFamilyIDLength = 16

	attributesFlagsOffset    = 928
	attributesXFRMOffset     = 936
	attributeMaskFlagsOffset = 944
	attributeMaskXFRMOffset  = 952

	mrEnclaveOffset = 960
	mrEnclaveLength = 32

	isvExtProdIDOffset = 1008
	isvExtProdIDLength = 16

	isvProdIDOffset = 1024
	isvSVNOffset    = 1026
)

var (
	header1Magic = []byte{0x06, 0x00, 0x00, 0x00, 0xE1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00}
	header2Magic = []byte{0x01, 0x01, 0x00, 0x00, 0x60, 0x00, 0x00, 0x00, 0x60, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00}
)

type SigstructInfo struct {
	HeaderVendor       uint32 `json:"header_vendor"`
	Date               uint32 `json:"date"`
	MREnclave          string `json:"mrenclave"`
	MRSigner           string `json:"mrsigner"`
	ISVProdID          uint16 `json:"isv_prod_id"`
	ISVSVN             uint16 `json:"isv_svn"`
	MiscSelect         string `json:"misc_select"`
	MiscMask           string `json:"misc_mask"`
	AttributesFlags    string `json:"attributes_flags"`
	AttributesXFRM     string `json:"attributes_xfrm"`
	AttributeMaskFlags string `json:"attribute_mask_flags"`
	AttributeMaskXFRM  string `json:"attribute_mask_xfrm"`
	ISVFamilyID        string `json:"isv_family_id,omitempty"`
	ISVExtProdID       string `json:"isvext_prod_id,omitempty"`
	RawSigstructHex    string `json:"raw_sigstruct_hex,omitempty"`
}

func isValidSigstruct(data []byte) bool {
	if len(data) < SigstructSize {
		return false
	}
	if !bytes.Equal(data[header1Offset:header1Offset+header1Length], header1Magic) {
		return false
	}
	if !bytes.Equal(data[header2Offset:header2Offset+header2Length], header2Magic) {
		return false
	}
	return true
}

func ParseSigstruct(data []byte) (*SigstructInfo, error) {
	if !isValidSigstruct(data) {
		return nil, errors.New("data does not contain a valid Intel SGX SIGSTRUCT header")
	}

	rsaPublicKeyModulus := data[rsaModulusOffset : rsaModulusOffset+rsaModulusLength]
	mrSignerDigest := sha256.Sum256(rsaPublicKeyModulus)
	mrEnclave := data[mrEnclaveOffset : mrEnclaveOffset+mrEnclaveLength]
	isvFamilyID := data[isvFamilyIDOffset : isvFamilyIDOffset+isvFamilyIDLength]
	isvExtProdID := data[isvExtProdIDOffset : isvExtProdIDOffset+isvExtProdIDLength]

	return &SigstructInfo{
		HeaderVendor:       binary.LittleEndian.Uint32(data[vendorOffset : vendorOffset+4]),
		Date:               binary.LittleEndian.Uint32(data[dateOffset : dateOffset+4]),
		MREnclave:          hex.EncodeToString(mrEnclave),
		MRSigner:           hex.EncodeToString(mrSignerDigest[:]),
		ISVProdID:          binary.LittleEndian.Uint16(data[isvProdIDOffset : isvProdIDOffset+2]),
		ISVSVN:             binary.LittleEndian.Uint16(data[isvSVNOffset : isvSVNOffset+2]),
		MiscSelect:         fmt.Sprintf("0x%08x", binary.LittleEndian.Uint32(data[miscSelectOffset:miscSelectOffset+4])),
		MiscMask:           fmt.Sprintf("0x%08x", binary.LittleEndian.Uint32(data[miscMaskOffset:miscMaskOffset+4])),
		AttributesFlags:    fmt.Sprintf("0x%016x", binary.LittleEndian.Uint64(data[attributesFlagsOffset:attributesFlagsOffset+8])),
		AttributesXFRM:     fmt.Sprintf("0x%016x", binary.LittleEndian.Uint64(data[attributesXFRMOffset:attributesXFRMOffset+8])),
		AttributeMaskFlags: fmt.Sprintf("0x%016x", binary.LittleEndian.Uint64(data[attributeMaskFlagsOffset:attributeMaskFlagsOffset+8])),
		AttributeMaskXFRM:  fmt.Sprintf("0x%016x", binary.LittleEndian.Uint64(data[attributeMaskXFRMOffset:attributeMaskXFRMOffset+8])),
		ISVFamilyID:        hex.EncodeToString(isvFamilyID),
		ISVExtProdID:       hex.EncodeToString(isvExtProdID),
		RawSigstructHex:    hex.EncodeToString(data[:SigstructSize]),
	}, nil
}

func findSigstructInELF(filePath string) ([]byte, error) {
	elfFile, err := elf.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("opening ELF %q: %w", filePath, err)
	}
	defer elfFile.Close()

	if sgxMetaSection := elfFile.Section(".note.sgxmeta"); sgxMetaSection != nil {
		if sectionBytes, err := sgxMetaSection.Data(); err == nil {
			if sigstructBytes := findSigstructInBytes(sectionBytes); sigstructBytes != nil {
				return sigstructBytes, nil
			}
		}
	}

	for _, section := range elfFile.Sections {
		sectionBytes, err := section.Data()
		if err != nil {
			continue
		}
		if sigstructBytes := findSigstructInBytes(sectionBytes); sigstructBytes != nil {
			return sigstructBytes, nil
		}
	}

	return nil, errors.New("SIGSTRUCT not found in ELF sections")
}

func findSigstructInBytes(data []byte) []byte {
	if len(data) >= SigstructSize && isValidSigstruct(data) {
		return data[:SigstructSize]
	}

	searchOffset := 0
	for {
		headerMatchIndex := bytes.Index(data[searchOffset:], header1Magic)
		if headerMatchIndex == -1 {
			break
		}
		candidateOffset := searchOffset + headerMatchIndex
		if candidateOffset+SigstructSize <= len(data) {
			candidateSlice := data[candidateOffset : candidateOffset+SigstructSize]
			if isValidSigstruct(candidateSlice) {
				return candidateSlice
			}
		}
		searchOffset = candidateOffset + 1
	}

	return nil
}

func ExtractSigstruct(filePath string) ([]byte, error) {
	if sigstructBytes, err := findSigstructInELF(filePath); err == nil && sigstructBytes != nil {
		return sigstructBytes, nil
	}

	rawFileBytes, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("reading file %q: %w", filePath, err)
	}

	if sigstructBytes := findSigstructInBytes(rawFileBytes); sigstructBytes != nil {
		return sigstructBytes, nil
	}

	return nil, fmt.Errorf("no valid Intel SGX SIGSTRUCT found in %q", filePath)
}

func writeOutputFile(filePath string, data []byte) error {
	if directory := filepath.Dir(filePath); directory != "." {
		if err := os.MkdirAll(directory, 0o755); err != nil {
			return fmt.Errorf("creating directory %q: %w", directory, err)
		}
	}
	if err := os.WriteFile(filePath, data, 0o644); err != nil {
		return fmt.Errorf("writing file %q: %w", filePath, err)
	}
	return nil
}

func run(args []string) error {
	flagSet := flag.NewFlagSet("extract_sigstruct", flag.ContinueOnError)
	var jsonMetadataOutputPath string
	flagSet.StringVar(&jsonMetadataOutputPath, "json", "", "Optional path to output parsed metadata as JSON")

	flagSet.Usage = func() {
		fmt.Fprintf(flagSet.Output(), "Usage: %s [flags] <input_enclave_or_so> [output_sigstruct_raw] [output_json]\n", flagSet.Name())
		fmt.Fprintln(flagSet.Output(), "\nFlags:")
		flagSet.PrintDefaults()
	}

	if err := flagSet.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}

	positionalArgs := flagSet.Args()
	if len(positionalArgs) < 1 {
		flagSet.Usage()
		return errors.New("missing input file argument")
	}

	inputEnclavePath := positionalArgs[0]
	var rawSigstructOutputPath string
	if len(positionalArgs) > 1 {
		rawSigstructOutputPath = positionalArgs[1]
	}
	if len(positionalArgs) > 2 && jsonMetadataOutputPath == "" {
		jsonMetadataOutputPath = positionalArgs[2]
	}

	sigstructBytes, err := ExtractSigstruct(inputEnclavePath)
	if err != nil {
		return err
	}

	sigstructInfo, err := ParseSigstruct(sigstructBytes)
	if err != nil {
		return fmt.Errorf("parsing SIGSTRUCT: %w", err)
	}

	if rawSigstructOutputPath != "" {
		if err := writeOutputFile(rawSigstructOutputPath, sigstructBytes); err != nil {
			return err
		}
		fmt.Printf("Wrote SIGSTRUCT binary (%d bytes) to: %s\n", len(sigstructBytes), rawSigstructOutputPath)
	}

	if jsonMetadataOutputPath != "" {
		jsonData, err := json.MarshalIndent(sigstructInfo, "", "  ")
		if err != nil {
			return fmt.Errorf("marshaling JSON: %w", err)
		}
		if err := writeOutputFile(jsonMetadataOutputPath, jsonData); err != nil {
			return err
		}
		fmt.Printf("Wrote SIGSTRUCT metadata JSON to: %s\n", jsonMetadataOutputPath)
	}

	fmt.Printf("Input: %s\n", filepath.Base(inputEnclavePath))
	fmt.Printf("SIGSTRUCT Length: %d bytes\n", len(sigstructBytes))
	fmt.Printf("MRENCLAVE: %s\n", sigstructInfo.MREnclave)
	fmt.Printf("MRSIGNER: %s\n", sigstructInfo.MRSigner)
	fmt.Printf("ISVPRODID: %d\n", sigstructInfo.ISVProdID)
	fmt.Printf("ISVSVN: %d\n", sigstructInfo.ISVSVN)
	return nil
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
