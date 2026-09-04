/*
verify_svsm.go implements the "gotpm verify debug svsm" command to debug and verify
an SVSM-based vTPM attestation report (SevSnpSvsmAttestation).

It supports two manifest verification modes depending on the manifest version:

1. Version 0 Manifest (Legacy / Challenge-based):
  - Proves AK co-residency using the interactive TCG EK-based key attestation protocol.
  - Requires specifying both --ek-pub and --certified-ak-blob (produced via "solve-challenge").
  - Enforces the use of --key=AK (Owner hierarchy AK certified against the EK).

2. Version 1 Manifest (New / Manifest-based):
  - Bypasses the interactive activation challenge by leveraging SVSM's signed manifest.
  - SVSM (VMPL0) derives the standard EK and AK on the fly under the Endorsement Hierarchy
    (using the vTPM's Endorsement Seed and fixed templates) and embeds their public areas in
    the manifest.
  - The guest VM (VMPL2) also derives its AK (using --key=gceAK) by querying the same template
    SVSM saved to the Google NV index under the Endorsement Hierarchy.
*/
package cmd

import (
	"bytes"
	"crypto"
	"crypto/sha512"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	apb "github.com/google/go-tpm-tools/proto/attest"
	"google.golang.org/protobuf/proto"

	"github.com/google/gce-tcb-verifier/gcetcbendorsement"
	epb "github.com/google/gce-tcb-verifier/proto/endorsement"
	tcbv "github.com/google/gce-tcb-verifier/verify"
	sabi "github.com/google/go-sev-guest/abi"
	"github.com/google/go-sev-guest/validate"
	"github.com/google/go-sev-guest/verify"
	"github.com/google/go-sev-guest/verify/trust"
	tpb "github.com/google/go-tpm-tools/proto/tpm"
	"github.com/google/go-tpm-tools/server"
	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/spf13/cobra"
)

var (
	certifiedAKBlobPath string
	trustedEKPub        string
)

func addCertifiedAKBlobFlag(cmd *cobra.Command) {
	cmd.PersistentFlags().StringVar(&certifiedAKBlobPath, "certified-ak-blob", "",
		"Specify path to certified AK blob produced from TPM registration.")
}

func addEKPubFlag(cmd *cobra.Command) {
	cmd.PersistentFlags().StringVar(&trustedEKPub, "ek-pub", "",
		"Specify path to EK pub used in TPM registration.")
}

var verifySVSMCmd = &cobra.Command{
	Use:   "svsm",
	Short: `Debug the contents of an SevSnpSvsmAttestation. Currently only supported with sev-snp. For debugging purposes only.`,
	RunE: func(*cobra.Command, []string) error {
		if teeTechnology != SevSnp {
			return errors.New("--svsm is only supported with --tee-technology=sev-snp")
		}
		if len(teeNonce) == 0 {
			return errors.New("tee-nonce should be specified when using verify debug svsm")
		}
		if trustedEKPub == "" {
			return fmt.Errorf("ek-pub is required")
		}
		svsmAttestation := &apb.SevSnpSvsmAttestation{}
		err := readProtoFromPath(input, svsmAttestation)
		if err != nil {
			return fmt.Errorf("failed to read svsm attestation: %w", err)
		}

		version := svsmAttestation.GetVtpmServiceManifestVersion()
		if version == "" {
			version = "0"
		}
		if version == "0" && key != "AK" {
			return fmt.Errorf("verifying manifest version 0 requires --key=AK")
		}
		if version == "1" && key != "gceAK" {
			return fmt.Errorf("verifying manifest version 1 requires --key=gceAK")
		}

		akPub, err := loadTrustedAKPub()
		if err != nil {
			return err
		}

		ekpub, err := readBytes(trustedEKPub)
		if err != nil {
			return fmt.Errorf("failed to read ek-pub: %w", err)
		}

		rot, err := getRootOfTrust()
		if err != nil {
			return fmt.Errorf("failed to get root of trust: %w", err)
		}
		err = verifySEVSNPSVSMAttestation(verifySEVSNPSVSMOpts{
			TEENonce:      teeNonce,
			SevVerifyOpts: &verify.Options{},
			SevValidateOpts: &validate.Options{
				GuestPolicy: sabi.SnpPolicy{
					SMT: true,
				},
			},
			EndorsementOpts: &tcbv.Options{
				RootsOfTrust: rot,
				Now:          time.Now(),
			},
			AKPub: akPub,
			EKPub: ekpub,
		}, svsmAttestation)
		if err != nil {
			return fmt.Errorf("failed to verify snp svsm attestation: %w", err)
		}

		pub, err := tpm2.DecodePublic(svsmAttestation.GetAttestation().GetAkPub())
		if err != nil {
			return err
		}
		cryptoPub, err := pub.Key()
		if err != nil {
			return err
		}
		ms, err := server.VerifyAttestation(svsmAttestation.GetAttestation(), server.VerifyOpts{Nonce: nonce, TrustedAKs: []crypto.PublicKey{cryptoPub}})
		if err != nil {
			return fmt.Errorf("verifying TPM attestation: %w", err)
		}
		ms.TeeAttestation = &apb.MachineState_SevSnpAttestation{
			SevSnpAttestation: svsmAttestation.SevSnpAttestation,
		}
		out, err := marshalOptions.Marshal(ms)
		if err != nil {
			return nil
		}
		if _, err := dataOutput().Write(out); err != nil {
			return fmt.Errorf("failed to write verified attestation report: %v", err)
		}
		return nil
	},
}

// loadTrustedAKPub retrieves the trusted Attestation Key (AK) public area either by
// reading it from a certified AK blob file (if --certified-ak-blob is provided) or by
// opening the local TPM and loading the key based on --key and --algo.
func loadTrustedAKPub() ([]byte, error) {
	if certifiedAKBlobPath != "" {
		blob := &tpb.CertifiedBlob{}
		if err := readProtoFromPath(certifiedAKBlobPath, blob); err != nil {
			return nil, fmt.Errorf("failed to read certified ak blob: %w", err)
		}
		return blob.PubArea, nil
	}

	rwc, err := openTpm()
	if err != nil {
		return nil, fmt.Errorf("failed to open TPM to retrieve AK: %w", err)
	}
	defer rwc.Close()

	algoToCreateAK, ok := attestationKeys[key]
	if !ok {
		return nil, fmt.Errorf("invalid --key value: %s", key)
	}
	createFunc, ok := algoToCreateAK[keyAlgo]
	if !ok {
		return nil, fmt.Errorf("invalid --algo value for key %s", key)
	}
	attestationKey, err := createFunc(rwc)
	if err != nil {
		return nil, fmt.Errorf("failed to load attestation key: %w", err)
	}
	defer attestationKey.Close()

	pubAreaBytes, err := attestationKey.PublicArea().Encode()
	if err != nil {
		return nil, fmt.Errorf("failed to encode AK public area: %w", err)
	}
	return pubAreaBytes, nil
}

func getRootOfTrust() (*x509.CertPool, error) {
	data, err := trust.DefaultHTTPSGetter().Get(gcetcbendorsement.DefaultRootURL)
	if err != nil {
		return nil, fmt.Errorf("failed to get root certificate: %w", err)
	}
	// Certificate may be PEM, but also may be DER.
	rot := x509.NewCertPool()
	if !rot.AppendCertsFromPEM(data) {
		rootCert, err := x509.ParseCertificate(data)
		if err != nil {
			return nil, fmt.Errorf("failed to parse root certificate as PEM or DER")
		}
		rot.AddCert(rootCert)
	}
	return rot, nil
}

// Options to configure verifySEVSNPSVSMAttestation.
type verifySEVSNPSVSMOpts struct {
	// Nonce that was used to generate the SNP attestation report while using SVSM as service provider.
	TEENonce []byte
	// Options for verifying the SNP attestation report, leave as nil to skip report verification.
	SevVerifyOpts *verify.Options
	// The validation options for VMPL, measurement, and report data will be overwritten to undertake the expected values for SVSM.
	// Validation options should not be left as nil.
	SevValidateOpts *validate.Options
	// Options for verifying the VMLaunchEndorsement, leave as nil to skip verifying endorsement
	EndorsementOpts *tcbv.Options
	// An AKPub that is trusted.
	// For vtpm service manifest version 0, this should be sourced from a TPM
	// registration process such as seen in client/import_certify.go.
	AKPub []byte
	// EkPub that the AKPub is co-resident with.
	EKPub []byte
}

// verifySEVSNPSVSMAttestation checks the SNP attestation report, values in it,
// and bindings between the SVSM vTPM, SNP attestation report, and vTPM service
// manifest. To verify the launch measurement in the attestation report, we
// also verify the endorsement itself.
func verifySEVSNPSVSMAttestation(svsmOpts verifySEVSNPSVSMOpts, svsmAttestation *apb.SevSnpSvsmAttestation) error {
	var err error
	if svsmOpts.SevVerifyOpts != nil {
		err = verify.SnpAttestation(svsmAttestation.GetSevSnpAttestation(), svsmOpts.SevVerifyOpts)
		if err != nil {
			return fmt.Errorf("SNP attestation verification failed: %w", err)
		}
	}

	svsmVMPL := 0
	svsmOpts.SevValidateOpts.VMPL = &svsmVMPL
	svsmOpts.SevValidateOpts.Measurement, err = getExpectedMeasurement(svsmAttestation.GetLaunchEndorsement())
	if err != nil {
		return fmt.Errorf("failed to get expected svsm measurement: %w", err)
	}
	svsmOpts.SevValidateOpts.ReportData, err = getExpectedReportData(svsmOpts, svsmAttestation)
	if err != nil {
		return fmt.Errorf("failed to get expected report data: %w", err)
	}
	err = validate.SnpAttestation(svsmAttestation.GetSevSnpAttestation(), svsmOpts.SevValidateOpts)
	if err != nil {
		return fmt.Errorf("SNP attestation validation failed: %w", err)
	}

	if svsmOpts.EndorsementOpts != nil {
		err = tcbv.Endorsement(svsmAttestation.LaunchEndorsement, svsmOpts.EndorsementOpts)
		if err != nil {
			return fmt.Errorf("failed to verify launch endorsement: %w", err)
		}
	}

	if !bytes.Equal(svsmOpts.AKPub, svsmAttestation.Attestation.GetAkPub()) {
		return errors.New("certified AK does not match attested AK")
	}
	return nil
}

// getExpectedReportData the expected report data for the v0 or v1 vtpm service manifest version
// defined in the SVSM specification at https://www.amd.com/en/developer/sev.html
// This corresponds to attest_single_vtpm() defined in
// https://github.com/coconut-svsm/svsm/blob/main/kernel/src/protocols/attest.rs#L336
func getExpectedReportData(svsmOpts verifySEVSNPSVSMOpts, svsmAttestation *apb.SevSnpSvsmAttestation) ([]byte, error) {
	version := svsmAttestation.GetVtpmServiceManifestVersion()
	if version == "" {
		version = "0"
	}
	switch version {
	case "0":
		if !bytes.Equal(svsmOpts.EKPub, svsmAttestation.VtpmServiceManifest) {
			return nil, errors.New("service manifest does not match EK pub that was certified against")
		}
	case "1":
		// - Offset 0x000 (4 bytes): Version (1)
		// - Offset 0x004 (4 bytes): Number of TPM2B_PUBLIC structures present
		// - Offset 0x008 (Variable): Concatenated TPM2B_PUBLIC structures
		manifest := svsmAttestation.VtpmServiceManifest
		if len(manifest) < 8 {
			return nil, fmt.Errorf("malformed service manifest: too short for v1 header (got %d bytes, want at least 8)", len(manifest))
		}
		manifestVer := binary.BigEndian.Uint32(manifest[0:4])
		if manifestVer != 1 {
			return nil, fmt.Errorf("unsupported service manifest version in payload: %d, expected 1", manifestVer)
		}
		numKeys := binary.BigEndian.Uint32(manifest[4:8])
		if numKeys < 2 {
			return nil, fmt.Errorf("malformed service manifest: expected at least 2 keys, got %d", numKeys)
		}
		manifest = manifest[8:]

		foundAK := false
		foundEK := false
		for i := uint32(0); i < numKeys; i++ {
			if len(manifest) == 0 {
				return nil, fmt.Errorf("malformed service manifest: count does not match number of keys: expected %d keys, got %d", numKeys, i)
			}
			if len(manifest) < 2 {
				return nil, fmt.Errorf("malformed service manifest: too short to read key size for key %d", i)
			}
			// Read the 2-byte size of the TPMT_PUBLIC area.
			size := binary.BigEndian.Uint16(manifest[:2])
			keyLen := int(size) + 2
			if len(manifest) < keyLen {
				return nil, fmt.Errorf("malformed service manifest: size %d exceeds remaining bytes %d for key %d", size, len(manifest)-2, i)
			}
			// keyBytes is the full TPM2B_PUBLIC structure.
			keyBytes := manifest[:keyLen]
			// svsmOpts.AKPub and svsmOpts.EKPub are in TPMT_PUBLIC format (no size prefix).
			// To compare them, we strip the 2-byte size prefix from keyBytes to get the TPMT_PUBLIC part.
			tpmtKeyBytes := keyBytes[2:]
			if bytes.Equal(svsmOpts.AKPub, tpmtKeyBytes) {
				foundAK = true
			}
			if bytes.Equal(svsmOpts.EKPub, tpmtKeyBytes) {
				foundEK = true
			}
			manifest = manifest[keyLen:]
		}
		if len(manifest) > 0 {
			return nil, fmt.Errorf("malformed service manifest: count does not match number of keys: %d trailing bytes after parsing %d keys", len(manifest), numKeys)
		}
		if !foundAK {
			return nil, errors.New("service manifest does not contain the AK pub that was certified against")
		}
		if !foundEK {
			return nil, errors.New("service manifest does not contain the EK pub")
		}
	default:
		return nil, errors.New("only vtpm service manifest version 0 or 1 is supported")
	}
	h := sha512.New()
	if len(svsmOpts.TEENonce) != sabi.ReportDataSize {
		return nil, fmt.Errorf("the teeNonce size is %d. SEV-SNP device requires 64", len(svsmOpts.TEENonce))
	}
	h.Write(svsmOpts.TEENonce[:])
	h.Write(svsmAttestation.GetVtpmServiceManifest())
	return h.Sum(nil), nil
}

func getExpectedMeasurement(endorsement []byte) ([]byte, error) {
	LaunchEndorsement := &epb.VMLaunchEndorsement{}
	err := proto.Unmarshal(endorsement, LaunchEndorsement)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal endorsement: %w", err)
	}
	golden := &epb.VMGoldenMeasurement{}
	err = proto.Unmarshal(LaunchEndorsement.GetSerializedUefiGolden(), golden)
	if err != nil {
		return nil, fmt.Errorf("failed to unserialize golden uefi: %w", err)
	}
	return golden.GetSevSnp().GetSvsmMeasurement(), nil
}
