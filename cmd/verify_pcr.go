package cmd

import (
	"crypto"
	"fmt"
	"io"

	"github.com/google/go-attestation/attest"
	"github.com/google/go-tpm-tools/client"
	pb "github.com/google/go-tpm-tools/proto/tpm"
	legacytpm2 "github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/googleipmi"
	"github.com/spf13/cobra"
)

var (
	verifyPcrHashAlgo = legacytpm2.AlgUnknown
)

func readPCRsIPMI(tpm transport.TPM, hashAlgo tpm2.TPMAlgID, pcrs []int) (*pb.PCRs, error) {
	pcrData := &pb.PCRs{
		Hash: pb.HashAlgo(hashAlgo),
		Pcrs: make(map[uint32][]byte),
	}

	// If no PCRs were specified, default to all 24 PCRs.
	if len(pcrs) == 0 {
		pcrs = make([]int, 24)
		for i := 0; i < 24; i++ {
			pcrs[i] = i
		}
	}

	// Read the requested PCRs in chunks of 8 to be safe and match standard behavior.
	for i := 0; i < len(pcrs); i += 8 {
		end := min(i+8, len(pcrs))
		chunk := pcrs[i:end]

		pcrSelect := make([]byte, 3)
		for _, pcr := range chunk {
			pcrSelect[pcr/8] |= 1 << (pcr % 8)
		}

		resp, err := tpm2.PCRRead{
			PCRSelectionIn: tpm2.TPMLPCRSelection{
				PCRSelections: []tpm2.TPMSPCRSelection{
					{
						Hash:      hashAlgo,
						PCRSelect: pcrSelect,
					},
				},
			},
		}.Execute(tpm)
		if err != nil {
			return nil, err
		}

		digestIdx := 0
		for _, pcr := range chunk {
			if len(resp.PCRSelectionOut.PCRSelections) > 0 {
				selOut := resp.PCRSelectionOut.PCRSelections[0].PCRSelect
				if (selOut[pcr/8] & (1 << (pcr % 8))) != 0 {
					if digestIdx >= len(resp.PCRValues.Digests) {
						return nil, fmt.Errorf("mismatch in returned PCR digests count")
					}
					pcrData.Pcrs[uint32(pcr)] = resp.PCRValues.Digests[digestIdx].Buffer
					digestIdx++
				}
			}
		}
	}

	return pcrData, nil
}

var verifyPcrCmd = &cobra.Command{
	Use:   "pcr",
	Short: "Verify the TPM PCR contents against the event log",
	Long:  `Verify the TPM PCR contents against the event log using standard TPM interface or Google IPMI transport.`,
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		var rwc io.ReadWriteCloser
		var tpmCloser interface {
			transport.TPM
			io.Closer
		}
		var err error

		if useIPMI {
			fmt.Fprintln(debugOutput(), "Connecting to Titan TPM via Google IPMI interface...")
			tpmCloser, err = googleipmi.Open()
			if err != nil {
				return fmt.Errorf("connecting to TPM via Google IPMI: %w", err)
			}
			defer tpmCloser.Close()

			rwc = tpmWrapper{struct {
				io.ReadWriter
				io.Closer
			}{
				transport.ToReadWriter(tpmCloser),
				tpmCloser,
			}}
		} else {
			rwc, err = openTpm()
			if err != nil {
				return err
			}
			defer rwc.Close()
		}

		fmt.Fprintln(debugOutput(), "Retrieving TCG event log...")
		eventLogBytes, err := client.GetEventLog(rwc)
		if err != nil {
			return fmt.Errorf("retrieving event log: %w", err)
		}
		fmt.Fprintf(debugOutput(), "Retrieved event log (%d bytes) successfully.\n", len(eventLogBytes))

		// Parse raw event log using go-attestation
		el, err := attest.ParseEventLog(eventLogBytes)
		if err != nil {
			return fmt.Errorf("parsing event log: %w", err)
		}

		var banks []*pb.PCRs
		if useIPMI {
			hashAlgo := tpm2.TPMAlgSHA256
			if verifyPcrHashAlgo != legacytpm2.AlgUnknown {
				hashAlgo = tpm2.TPMAlgID(verifyPcrHashAlgo)
			}
			fmt.Fprintf(debugOutput(), "Reading PCRs for bank %v via IPMI native command...\n", hashAlgo)
			pcrData, err := readPCRsIPMI(tpmCloser, hashAlgo, pcrs)
			if err != nil {
				return fmt.Errorf("reading PCRs for bank %v via IPMI: %w", hashAlgo, err)
			}
			banks = append(banks, pcrData)
		} else {
			if verifyPcrHashAlgo != legacytpm2.AlgUnknown {
				sel := legacytpm2.PCRSelection{Hash: verifyPcrHashAlgo, PCRs: pcrs}
				if len(sel.PCRs) == 0 {
					sel = client.FullPcrSel(verifyPcrHashAlgo)
				}
				fmt.Fprintf(debugOutput(), "Reading PCRs for bank %v...\n", verifyPcrHashAlgo)
				pcrData, err := client.ReadPCRs(rwc, sel)
				if err != nil {
					return fmt.Errorf("reading PCRs for bank %v: %w", verifyPcrHashAlgo, err)
				}
				banks = append(banks, pcrData)
			} else {
				fmt.Fprintln(debugOutput(), "Reading PCRs for all allocated banks...")
				var err error
				banks, err = client.ReadAllPCRs(rwc)
				if err != nil {
					return fmt.Errorf("reading all PCRs: %w", err)
				}
			}
		}

		for _, bank := range banks {
			algo := legacytpm2.Algorithm(bank.GetHash())
			fmt.Fprintf(debugOutput(), "Verifying PCR bank %v against event log...\n", algo)

			var cryptoHash crypto.Hash
			switch algo {
			case legacytpm2.AlgSHA1:
				cryptoHash = crypto.SHA1
			case legacytpm2.AlgSHA256:
				cryptoHash = crypto.SHA256
			case legacytpm2.AlgSHA384:
				cryptoHash = crypto.SHA384
			case legacytpm2.AlgSHA512:
				cryptoHash = crypto.SHA512
			default:
				return fmt.Errorf("unsupported hash algorithm %v for verification", algo)
			}

			var attestPCRs []attest.PCR
			for pcrIndex, digest := range bank.GetPcrs() {
				attestPCRs = append(attestPCRs, attest.PCR{
					Index:     int(pcrIndex),
					Digest:    digest,
					DigestAlg: cryptoHash,
				})
			}

			_, err = el.Verify(attestPCRs)
			if err != nil {
				return fmt.Errorf("failed to verify PCR bank %v: %w", algo, err)
			}
			fmt.Fprintf(messageOutput(), "PCR bank %v contents verified successfully against event log.\n", algo)
		}

		fmt.Fprintln(messageOutput(), "TPM PCR contents are valid.")
		return nil
	},
}

func init() {
	verifyCmd.AddCommand(verifyPcrCmd)
	addHashAlgoFlag(verifyPcrCmd, &verifyPcrHashAlgo)
	addEventLogFlag(verifyPcrCmd)
	addPCRsFlag(verifyPcrCmd)
}
