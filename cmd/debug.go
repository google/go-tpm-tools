package cmd

import (
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"net/http"
	"unicode"

	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm-tools/server"
	"github.com/google/go-tpm/tpm2"
	"github.com/spf13/cobra"
	"google.golang.org/protobuf/reflect/protoreflect"

	pb "github.com/google/go-tpm-tools/proto/attest"
)

var debugCmd = &cobra.Command{
	Use:   "debug",
	Short: "Output attestation related data",
	Long: `Output parts of the Attestation and MachineState Protobufs

This command is UNSTABLE, and may change at any time. Right now, these functions
only work on Google Compute Engine (GCE) VMs.`,
	Args: cobra.NoArgs,
}

var attCmd = &cobra.Command{
	Use:   "attestation",
	Short: "Output all or part of the Attestation Protobuf",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		m, err := getAttestation()
		if err != nil {
			return err
		}
		return outputProto(m)
	},
}

var certsCmd = &cobra.Command{
	Use:   "certs",
	Short: "Output all Attestation Certificates in PEM format",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		m, err := getAttestation()
		if err != nil {
			return err
		}

		certs := []*x509.Certificate{}
		if len(m.GetAkCert()) > 0 {
			akcert, err := x509.ParseCertificate(m.GetAkCert())
			if err != nil {
				return fmt.Errorf("parsing AK Certificate: %w", err)
			}
			certs = append(certs, akcert)
		}
		for i, certDER := range m.GetIntermediateCerts() {
			cert, err := x509.ParseCertificate(certDER)
			if err != nil {
				return fmt.Errorf("parsing Intermediate Certificate %d: %w", i, err)
			}
			certs = append(certs, cert)
		}

		for i, cert := range certs {
			block := &pem.Block{
				Type:  "CERTIFICATE",
				Bytes: cert.Raw,
			}
			if err := pem.Encode(dataOutput(), block); err != nil {
				return fmt.Errorf("encoding Certificate %d: %w", i, err)
			}
		}
		return nil
	},
}

var msCmd = &cobra.Command{
	Use:   "machine-state",
	Short: "Output all or part of the MachineState Protobuf",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		m, err := getMachineState()
		if err != nil {
			return err
		}
		return outputProto(m)
	},
}

var platCmd = &cobra.Command{
	Use:   "platform",
	Short: "Output the PlatformState Protobuf",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		m, err := getMachineState()
		if err != nil {
			return err
		}
		return outputProto(m.GetPlatform())
	},
}

var sbCmd = &cobra.Command{
	Use:   "secure-boot",
	Short: "Output the SecureBootState Protobuf",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		m, err := getMachineState()
		if err != nil {
			return err
		}
		return outputProto(m.GetSecureBoot())
	},
}

var eventsCmd = &cobra.Command{
	Use:   "events",
	Short: "Output the Event Protobufs for a PCR",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		eventMap, err := getEvents()
		if err != nil {
			return err
		}

		if len(pcrs) == 0 {
			pcrs = client.FullPcrSel(tpm2.AlgSHA256).PCRs
		}
		for _, pcr := range pcrs {
			events := eventMap[pcr]
			if len(events) == 0 {
				continue
			}

			fmt.Fprintf(dataOutput(), "PCR %d:\n", pcr)
			for _, event := range events {
				fmt.Fprintf(dataOutput(), "\tType: 0x%08x\n", event.GetUntrustedType())
				fmt.Fprintf(dataOutput(), "\t\tVerified: %v\n", event.GetDigestVerified())
				fmt.Fprintf(dataOutput(), "\t\tDigest (hex): %s\n", hex.EncodeToString(event.GetDigest()))

				// Print directly or as hex if this is a
				data := event.GetData()
				if isASCII(data) {
					fmt.Fprintf(dataOutput(), "\t\tData: %q\n", string(data))
				} else {
					fmt.Fprintf(dataOutput(), "\t\tData (hex): %s\n", hex.EncodeToString(data))
				}
				fmt.Fprintln(dataOutput())
			}
			fmt.Fprintln(dataOutput())
		}
		return nil
	},
}

var grubCmd = &cobra.Command{
	Use:   "grub",
	Short: "Output the GrubState Protobuf",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		m, err := getMachineState()
		if err != nil {
			return err
		}
		return outputProto(m.GetGrub())
	},
}

var linuxCmd = &cobra.Command{
	Use:   "linux",
	Short: "Output the LinuxKernelState Protobuf",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		m, err := getMachineState()
		if err != nil {
			return err
		}
		return outputProto(m.GetLinuxKernel())
	},
}

var cosCmd = &cobra.Command{
	Use:   "cos",
	Short: "Output the AttestedCosState Protobuf",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		m, err := getMachineState()
		if err != nil {
			return err
		}
		return outputProto(m.GetCos())
	},
}

var (
	debugNonce      = []byte{0, 1, 2, 3}
	debugAttestOpts = client.AttestOpts{
		Nonce:            debugNonce,
		CertChainFetcher: http.DefaultClient,
	}
	debugVerifyOpts = server.VerifyOpts{
		Nonce:            debugNonce,
		TrustedRootCerts: server.GceEKRoots,
		Loader:           server.GRUB,
	}
)

func getAttestation() (*pb.Attestation, error) {
	rwc, err := openTpm()
	if err != nil {
		return nil, err
	}
	defer rwc.Close()

	ak, err := client.GceAttestationKeyECC(rwc)
	if err != nil {
		return nil, fmt.Errorf("loading GCE Attestation Key: %w", err)
	}
	att, err := ak.Attest(debugAttestOpts)
	if err != nil {
		return nil, fmt.Errorf("fetching Attestation: %w", err)
	}
	return att, nil
}

func getMachineState() (*pb.MachineState, error) {
	att, err := getAttestation()
	if err != nil {
		return nil, err
	}
	ms, err := server.VerifyAttestation(att, debugVerifyOpts)
	if err != nil {
		return nil, fmt.Errorf("verifying attestation: %w", err)
	}
	return ms, nil
}

func getEvents() (map[int][]*pb.Event, error) {
	ms, err := getMachineState()
	if err != nil {
		return nil, err
	}
	events := make(map[int][]*pb.Event)
	for _, event := range ms.GetRawEvents() {
		idx := int(event.GetPcrIndex())
		events[idx] = append(events[idx], event)
	}
	return events, nil
}

func outputProto(m protoreflect.ProtoMessage) error {
	output, err := marshalOptions.Marshal(m)
	if err != nil {
		return fmt.Errorf("formatting protobuf: %w", err)
	}
	_, err = dataOutput().Write(output)
	return err
}

func isASCII(data []byte) bool {
	for _, b := range data {
		if b > unicode.MaxASCII {
			return false
		}
	}
	return true
}

func init() {
	RootCmd.AddCommand(debugCmd)
	addOutputFlag(debugCmd)

	debugCmd.AddCommand(attCmd)
	debugCmd.AddCommand(msCmd)

	attCmd.AddCommand(certsCmd)

	msCmd.AddCommand(platCmd)
	msCmd.AddCommand(sbCmd)
	msCmd.AddCommand(eventsCmd)
	addPCRsFlag(eventsCmd)
	msCmd.AddCommand(grubCmd)
	msCmd.AddCommand(linuxCmd)
	msCmd.AddCommand(cosCmd)
}
