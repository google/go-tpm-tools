// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"fmt"
	"os"

	"github.com/google/platform-attestation/titan/dice/scriberoots"
	"github.com/google/platform-attestation/titan/dice/titandice"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/googleipmi"
	"github.com/spf13/cobra"
)

var (
	titanInputPath  string
	titanOutputPath string
)

const (
	// NVRAM index where the Endorsement Key certificate chain is stored on Titan.
	ekCertChainNVIndex = 0x01c00100
)

var (
	// prodRwSigningKeyInfo represents the key info for the production
	// Read-Write firmware signing key.
	prodRwSigningKeyInfo = titandice.KeyInfo{0x47, 0x22, 0x4d, 0xc6}
)

func readNVIndexIPMI(tpm transport.TPM, nvIndex uint32, chunkSize int) ([]byte, error) {
	var data []byte
	offset := 0
	// A standard Titan DICE cert chain is exactly 608 to 640 bytes.
	// Let's read up to a maximum of 768 bytes to be absolutely sure we get everything.
	maxSize := 768

	for offset < maxSize {
		sizeToRead := chunkSize
		if offset+sizeToRead > maxSize {
			sizeToRead = maxSize - offset
		}

		fmt.Fprintf(debugOutput(), "Reading NV Index 0x%08x via IPMI: offset=%d, size=%d...\n", nvIndex, offset, sizeToRead)

		namedIndex := tpm2.NamedHandle{
			Handle: tpm2.TPMHandle(nvIndex),
			Name:   tpm2.TPM2BName{Buffer: []byte{1}}, // Dummy non-empty Name to satisfy go-tpm local validation
		}

		cmd := tpm2.NVRead{
			AuthHandle: namedIndex,
			NVIndex:    namedIndex,
			Size:       uint16(sizeToRead),
			Offset:     uint16(offset),
		}

		resp, err := cmd.Execute(tpm)
		if err != nil {
			// If we get an error, check if we already read some data.
			// Since we read in chunks, if we read past the end of the index,
			// the TPM will return an error (e.g. TPM_RC_NV_RANGE).
			// If we already successfully read some data, we can assume we hit the end of the index!
			if len(data) > 0 {
				fmt.Fprintf(debugOutput(), "NV Index read hit end boundary at offset %d (error: %v)\n", offset, err)
				break
			}
			return nil, err
		}

		if len(resp.Data.Buffer) == 0 {
			fmt.Fprintf(debugOutput(), "NV Index read returned 0 bytes at offset %d\n", offset)
			break
		}

		fmt.Fprintf(debugOutput(), "Successfully read %d bytes from NV Index\n", len(resp.Data.Buffer))
		data = append(data, resp.Data.Buffer...)
		offset += len(resp.Data.Buffer)

		// If we read less than the requested chunk size, we hit the end of the index!
		if len(resp.Data.Buffer) < sizeToRead {
			fmt.Fprintf(debugOutput(), "NV Index read reached EOF at offset %d\n", offset)
			break
		}
	}

	return data, nil
}

var verifyTitanCmd = &cobra.Command{
	Use:   "titan",
	Short: "Verify Titan DICE certificate chain",
	Long:  `Verify Titan DICE certificate chain retrieved via IPMI interface or from an offline file.`,
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		var certChainBytes []byte
		var err error

		if titanInputPath != "" {
			// Offline validation from file
			fmt.Fprintf(debugOutput(), "Reading offline certificate chain from: %s...\n", titanInputPath)
			certChainBytes, err = os.ReadFile(titanInputPath)
			if err != nil {
				return fmt.Errorf("reading cert chain from file %q: %w", titanInputPath, err)
			}
			fmt.Fprintf(debugOutput(), "Successfully read certificate chain file (%d bytes)\n", len(certChainBytes))
		} else {
			// Connect via IPMI
			fmt.Fprintln(debugOutput(), "Connecting to Titan TPM via Google IPMI interface...")
			tpmCloser, err := googleipmi.Open()
			if err != nil {
				return fmt.Errorf("connecting to TPM via Google IPMI: %w", err)
			}
			defer tpmCloser.Close()
			fmt.Fprintln(debugOutput(), "IPMI connection established successfully.")

			// Read NV RAM data directly using low-level NVRead command over IPMI in safe 32-byte chunks
			certChainBytes, err = readNVIndexIPMI(tpmCloser, ekCertChainNVIndex, 32)
			if err != nil {
				return fmt.Errorf("reading NV Index 0x%08x via IPMI: %w", ekCertChainNVIndex, err)
			}
			fmt.Fprintf(debugOutput(), "Successfully retrieved certificate chain via IPMI interface (%d bytes)\n", len(certChainBytes))

			// Save retrieved cert chain if output path is specified
			if titanOutputPath != "" {
				fmt.Fprintf(debugOutput(), "Saving retrieved certificate chain to: %s...\n", titanOutputPath)
				err = os.WriteFile(titanOutputPath, certChainBytes, 0644)
				if err != nil {
					return fmt.Errorf("writing retrieved cert chain to %q: %w", titanOutputPath, err)
				}
				fmt.Fprintf(debugOutput(), "Successfully saved certificate chain to %s\n", titanOutputPath)
			}
		}

		// Validate and verify the chain
		fmt.Fprintln(debugOutput(), "Loading trusted Scribe Root certificates...")
		roots, err := scriberoots.GetAllScribeRoots()
		if err != nil {
			return fmt.Errorf("retrieving scribe roots: %w", err)
		}
		fmt.Fprintf(debugOutput(), "Loaded %d trusted Scribe Root certificates successfully.\n", len(roots))

		var rootCerts [][]byte
		for _, root := range roots {
			rootCerts = append(rootCerts, root)
		}

		opts := &titandice.ValidateScribeCertificateChainOptions{
			ScribeCertificates: rootCerts,
			RwSigningKeyInfos:  []titandice.KeyInfo{prodRwSigningKeyInfo},
		}

		fmt.Fprintln(debugOutput(), "Initializing Titan DICE validator...")
		validator, err := titandice.NewValidator(opts)
		if err != nil {
			return fmt.Errorf("creating validator: %w", err)
		}

		fmt.Fprintln(debugOutput(), "Parsing Titan DICE certificate chain...")
		certChain, err := titandice.ParseTitanDiceScribeCertificateChain(certChainBytes)
		if err != nil {
			return fmt.Errorf("parsing certificate chain: %w", err)
		}
		fmt.Fprintf(debugOutput(), "Parsed AliasKeyCertificate: HWID=0x%x, HWCat=0x%x, BootloaderTag=0x%x\n",
			certChain.AliasKeyCertificate.Header.HWID,
			certChain.AliasKeyCertificate.Header.HWCat,
			certChain.AliasKeyCertificate.Header.BootloaderTag)
		fmt.Fprintf(debugOutput(), "Parsed DeviceIDCertificate: ScribeKeyID=0x%x, HWID=0x%x, HWCat=0x%x\n",
			certChain.DeviceIDCertificate.Header.ScribeKeyID,
			certChain.DeviceIDCertificate.Header.HWID,
			certChain.DeviceIDCertificate.Header.HWCat)
		fmt.Fprintf(debugOutput(), "Parsed DeviceIDScribeCertificate: DeviceIDCertHash=0x%x...\n",
			certChain.DeviceIDScribeCertificate.DeviceIDCertHash[0:8])

		fmt.Fprintln(debugOutput(), "Validating DICE Scribe certificate chain signatures and Root-of-Trust...")
		if err := titandice.ValidateScribeCertificateChain(certChain, validator); err != nil {
			return fmt.Errorf("certificate chain validation failed: %w", err)
		}
		fmt.Fprintln(debugOutput(), "DICE Scribe certificate chain signatures validated successfully against Scribe Roots.")

		fmt.Fprintln(messageOutput(), "Titan DICE Scribe certificate chain is valid.")
		return nil
	},
}

func init() {
	verifyCmd.AddCommand(verifyTitanCmd)
	verifyTitanCmd.Flags().StringVarP(&titanInputPath, "input", "i", "", "Path to input certificate chain file (offline mode)")
	verifyTitanCmd.Flags().StringVarP(&titanOutputPath, "output", "o", "", "Path to save retrieved certificate chain")
}
