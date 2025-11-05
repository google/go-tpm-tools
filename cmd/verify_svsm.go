package cmd

import (
	"bytes"
	"crypto"
	"crypto/sha512"
	"crypto/x509"
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

var errSvsmNeedsTeeNonce = errors.New("tee-nonce should be specified when using verify debug svsm")

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
			return errSvsmOnlySupportedWithSevSnp
		}
		if len(teeNonce) == 0 {
			return errSvsmNeedsTeeNonce
		}
		svsmAttestation := &apb.SevSnpSvsmAttestation{}
		err := readProtoFromPath(input, svsmAttestation)
		if err != nil {
			return fmt.Errorf("failed to read svsm attestation: %w", err)
		}

		blob := &tpb.CertifiedBlob{}
		err = readProtoFromPath(certifiedAKBlobPath, blob)
		if err != nil {
			return fmt.Errorf("failed to read certified ak blob: %w", err)
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
			AKPub: blob.PubArea,
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

var (
	errVtpmServiceManifestEkDoesntMatch      = errors.New("service manifest does not match EK pub that was certified against")
	errUnsupportedVTPMServiceManifestVersion = errors.New("only vtpm service manifest version 0 is supported")
	errMismatchingAK                         = errors.New("certified AK does not match attested AK")
)

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
		return errMismatchingAK
	}
	return nil
}

// getExpectedReportData the expected report data for the v0 vtpm service manifest version
// defined in the SVSM specification at https://www.amd.com/en/developer/sev.html
// This corresponds to attest_single_vtpm() defined in
// https://github.com/coconut-svsm/svsm/blob/main/kernel/src/protocols/attest.rs#L336
func getExpectedReportData(svsmOpts verifySEVSNPSVSMOpts, svsmAttestation *apb.SevSnpSvsmAttestation) ([]byte, error) {
	if svsmAttestation.GetVtpmServiceManifestVersion() != "0" {
		return nil, errUnsupportedVTPMServiceManifestVersion
	}
	if !bytes.Equal(svsmOpts.EKPub, svsmAttestation.VtpmServiceManifest) {
		return nil, errVtpmServiceManifestEkDoesntMatch
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
