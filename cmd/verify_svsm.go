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
    the manifest. The manifest is hashed into the SNP report's REPORT_DATA, so the AK is
    bound to the vTPM by the AMD-signed report alone.
  - Takes no out-of-band registration material: the trusted AK is taken from the
    attestation supplied via --input and checked for membership in the report-bound
    manifest. --certified-ak-blob is v0-only and is rejected here. --ek-pub is optional for
    verifying against the manifest
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
		"Specify path to certified AK blob produced from TPM registration. "+
			"Required for manifest version 0 and rejected for manifest version 1, where the "+
			"AK is taken from --input.")
}

func addEKPubFlag(cmd *cobra.Command) {
	cmd.PersistentFlags().StringVar(&trustedEKPub, "ek-pub", "",
		"Specify path to EK pub used in TPM registration. "+
			"Required for manifest version 0 and optional for manifest version 1.")
}

var verifySVSMCmd = &cobra.Command{
	Use:   "svsm",
	Short: `Debug the contents of an SevSnpSvsmAttestation. Currently only supported with sev-snp. For debugging purposes only.`,
	RunE: func(*cobra.Command, []string) error {
		if teeTechnology != sevSNP {
			return errors.New("--svsm is only supported with --tee-technology=sev-snp")
		}
		if len(teeNonce) == 0 {
			return errors.New("tee-nonce should be specified when using verify debug svsm")
		}
		svsmAttestation := &apb.SevSnpSvsmAttestation{}
		err := readProtoFromPath(input, svsmAttestation)
		if err != nil {
			return fmt.Errorf("failed to read svsm attestation: %w", err)
		}

		version := svsmAttestation.GetVtpmServiceManifestVersion()
		if version == "" {
			version = defaultConfigfsTsmReportServiceManifestVersion
		}

		var certifiedAKPub, ekPub []byte
		switch version {
		case "0":
			if key != "AK" {
				return fmt.Errorf("verifying manifest version 0 requires --key=AK")
			}
			// The v0 manifest is just the EK pub, so the SNP report says nothing about
			// the AK. Trust in the AK must come from out of band: the EK-based key
			// attestation protocol run by "gotpm register". Reading the AK from --input
			// here would be circular.
			if trustedEKPub == "" {
				return errors.New("ek-pub is required for manifest version 0")
			}
			if certifiedAKBlobPath == "" {
				return errors.New("certified-ak-blob is required for manifest version 0")
			}
			certifiedAKPub, err = readCertifiedAKPub()
			if err != nil {
				return err
			}
			ekPub, err = readBytes(trustedEKPub)
			if err != nil {
				return fmt.Errorf("failed to read ek-pub: %w", err)
			}
		case "1":
			if key != "gceAK" {
				return fmt.Errorf("verifying manifest version 1 requires --key=gceAK")
			}
			// The v1 manifest embeds both the EK and AK public areas, and SVSM at VMPL0
			// hashes it into the SNP report's REPORT_DATA. The AK carried in --input is
			// therefore already bound to the vTPM by the AMD-signed report, so sourcing
			// it from --input is not circular: verifyManifestAndKeys requires it to
			// appear in the report-bound manifest.
			// --certified-ak-blob is only needed for v0 key registration, so reject it here.
			if certifiedAKBlobPath != "" {
				return errors.New("certified-ak-blob is not supported with manifest version 1: the AK is taken from the attestation and checked against the manifest")
			}
			if trustedEKPub != "" {
				ekPub, err = readBytes(trustedEKPub)
				if err != nil {
					return fmt.Errorf("failed to read ek-pub: %w", err)
				}
			}
			if len(svsmAttestation.GetAttestation().GetAkPub()) == 0 {
				return errors.New("attestation does not contain an AK pub")
			}
		default:
			return fmt.Errorf("only vtpm service manifest version 0 or 1 is supported, got %q", version)
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
			CertifiedAKPub: certifiedAKPub,
			EKPub:          ekPub,
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
			return fmt.Errorf("failed to marshal machine state: %w", err)
		}
		if _, err := dataOutput().Write(out); err != nil {
			return fmt.Errorf("failed to write verified attestation report: %v", err)
		}
		return nil
	},
}

// readCertifiedAKPub retrieves the trusted Attestation Key (AK) public area from a
// certified AK blob file produced by "gotpm register solve-challenge".
func readCertifiedAKPub() ([]byte, error) {
	blob := &tpb.CertifiedBlob{}
	if err := readProtoFromPath(certifiedAKBlobPath, blob); err != nil {
		return nil, fmt.Errorf("failed to read certified ak blob: %w", err)
	}
	return blob.PubArea, nil
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
	// An out-of-band certified AK public area (TPMT_PUBLIC).
	// Required for vtpm service manifest version 0 (sourced from a TPM registration
	// process such as client/import_certify.go).
	// Unused (must be nil/empty) for vtpm service manifest version 1, where the AK
	// is taken from the attestation and verified against the report-bound manifest.
	CertifiedAKPub []byte
	// EK public area (TPMT_PUBLIC) that the AK is co-resident with.
	// Required for vtpm service manifest version 0, where it is the entire manifest
	// and is the only thing the SNP report commits to.
	// Optional for vtpm service manifest version 1: if provided, the manifest is
	// verified to contain it.
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
	svsmOpts.SevValidateOpts.ReportData, err = getExpectedReportData(svsmOpts.TEENonce, svsmAttestation.GetVtpmServiceManifest())
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

	if err := verifyManifestAndKeys(svsmOpts, svsmAttestation); err != nil {
		return fmt.Errorf("manifest and key verification failed: %w", err)
	}
	return nil
}

// getExpectedReportData returns the expected 64-byte REPORT_DATA digest for an
// SVSM vTPM attestation report: SHA512(teeNonce || vtpmServiceManifest).
// This corresponds to attest_single_vtpm() defined in
// https://github.com/coconut-svsm/svsm/blob/main/kernel/src/protocols/attest.rs#L336
func getExpectedReportData(teeNonce []byte, vtpmServiceManifest []byte) ([]byte, error) {
	if len(teeNonce) != sabi.ReportDataSize {
		return nil, fmt.Errorf("the teeNonce size is %d. SEV-SNP device requires 64", len(teeNonce))
	}
	h := sha512.New()
	h.Write(teeNonce)
	h.Write(vtpmServiceManifest)
	return h.Sum(nil), nil
}

// verifyManifestAndKeys verifies the vTPM service manifest contents and binds
// the attestation's AK (and optional EK) according to the manifest version:
//   - Version 0 (Challenge-based):
//     Reference values: svsmOpts.CertifiedAKPub and svsmOpts.EKPub (from out-of-band registration).
//     Checks that VtpmServiceManifest == svsmOpts.EKPub and Attestation.AkPub == svsmOpts.CertifiedAKPub.
//   - Version 1 (Manifest-based):
//     Reference value: VtpmServiceManifest (bound to the vTPM by the AMD-signed REPORT_DATA).
//     Checks that Attestation.AkPub ∈ VtpmServiceManifest and (if provided) svsmOpts.EKPub ∈ VtpmServiceManifest.
func verifyManifestAndKeys(svsmOpts verifySEVSNPSVSMOpts, svsmAttestation *apb.SevSnpSvsmAttestation) error {
	version := svsmAttestation.GetVtpmServiceManifestVersion()
	if version == "" {
		version = "0"
	}
	attestedAKPub := svsmAttestation.GetAttestation().GetAkPub()

	switch version {
	case "0":
		if !bytes.Equal(svsmOpts.EKPub, svsmAttestation.GetVtpmServiceManifest()) {
			return errors.New("service manifest does not match EK pub that was certified against")
		}
		if !bytes.Equal(svsmOpts.CertifiedAKPub, attestedAKPub) {
			return errors.New("certified AK does not match attested AK")
		}
		return nil

	case "1":
		if len(svsmOpts.CertifiedAKPub) > 0 {
			return errors.New("certified-ak-blob is not supported with manifest version 1: the AK is taken from the attestation and checked against the manifest")
		}
		if len(attestedAKPub) == 0 {
			return errors.New("attestation does not contain an AK pub")
		}
		if len(svsmOpts.EKPub) > 0 && bytes.Equal(attestedAKPub, svsmOpts.EKPub) {
			return errors.New("AK pub and EK pub cannot be identical")
		}

		// - Offset 0x000 (4 bytes): Version (1)
		// - Offset 0x004 (4 bytes): Number of TPM2B_PUBLIC structures present
		// - Offset 0x008 (Variable): Concatenated TPM2B_PUBLIC structures
		manifest := svsmAttestation.GetVtpmServiceManifest()
		if len(manifest) < 8 {
			return fmt.Errorf("malformed service manifest: too short for v1 header (got %d bytes, want at least 8)", len(manifest))
		}
		manifestVer := binary.BigEndian.Uint32(manifest[0:4])
		if manifestVer != 1 {
			return fmt.Errorf("unsupported service manifest version in payload: %d, expected 1", manifestVer)
		}
		numKeys := binary.BigEndian.Uint32(manifest[4:8])
		if numKeys < 2 {
			return fmt.Errorf("malformed service manifest: expected at least 2 keys, got %d", numKeys)
		}
		manifest = manifest[8:]

		foundAK := false
		foundEK := false
		for i := uint32(0); i < numKeys; i++ {
			if len(manifest) == 0 {
				return fmt.Errorf("malformed service manifest: count does not match number of keys: expected %d keys, got %d", numKeys, i)
			}
			if len(manifest) < 2 {
				return fmt.Errorf("malformed service manifest: too short to read key size for key %d", i)
			}
			// Read the 2-byte size of the TPMT_PUBLIC area.
			size := binary.BigEndian.Uint16(manifest[:2])
			keyLen := int(size) + 2
			if len(manifest) < keyLen {
				return fmt.Errorf("malformed service manifest: size %d exceeds remaining bytes %d for key %d", size, len(manifest)-2, i)
			}
			// Strip the 2-byte size prefix from TPM2B_PUBLIC to get the TPMT_PUBLIC part.
			tpmtKeyBytes := manifest[2:keyLen]
			if !foundAK && bytes.Equal(attestedAKPub, tpmtKeyBytes) {
				foundAK = true
			} else if !foundEK && len(svsmOpts.EKPub) > 0 && bytes.Equal(svsmOpts.EKPub, tpmtKeyBytes) {
				foundEK = true
			}
			manifest = manifest[keyLen:]
		}
		if len(manifest) > 0 {
			return fmt.Errorf("malformed service manifest: count does not match number of keys: %d trailing bytes after parsing %d keys", len(manifest), numKeys)
		}
		if !foundAK {
			return errors.New("service manifest does not contain the attested AK pub")
		}
		if len(svsmOpts.EKPub) > 0 && !foundEK {
			return errors.New("service manifest does not contain the EK pub")
		}
		return nil

	default:
		return fmt.Errorf("only vtpm service manifest version 0 or 1 is supported, got %q", version)
	}
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
