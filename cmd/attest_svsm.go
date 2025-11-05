package cmd

import (
	"errors"
	"fmt"
	"time"

	"github.com/google/gce-tcb-verifier/extract"
	"github.com/google/go-configfs-tsm/configfs/configfsi"
	"github.com/google/go-configfs-tsm/configfs/linuxtsm"
	"github.com/google/go-configfs-tsm/report"
	sabi "github.com/google/go-sev-guest/abi"
	sevpb "github.com/google/go-sev-guest/proto/sevsnp"
	"github.com/google/go-tpm-tools/client"
	apb "github.com/google/go-tpm-tools/proto/attest"
	"github.com/spf13/cobra"
	"google.golang.org/protobuf/proto"
)

var (
	errSVSMOnlySupportsAK          = errors.New("SVSM currently only support --key=AK")
	errSvsmOnlySupportedWithSevSnp = errors.New("--svsm is only supported with --tee-technology=sev-snp")
)

var attestSVSMCmd = &cobra.Command{
	Use:   "svsm",
	Short: `Produce a SevSnpSvsmAttestation that wraps the PCR attestation message.`,
	RunE: func(*cobra.Command, []string) error {
		if teeTechnology != SevSnp {
			return errSvsmOnlySupportedWithSevSnp
		}
		rwc, err := openTpm()
		if err != nil {
			return err
		}
		defer rwc.Close()

		var attestationKey *client.Key
		if key != "AK" {
			return errSVSMOnlySupportsAK
		}
		algoToCreateAK, ok := attestationKeys[key]
		if !ok {
			return fmt.Errorf("%v is an invalid value for --key, only AK is supported", key)
		}
		createFunc := algoToCreateAK[keyAlgo]
		attestationKey, err = createFunc(rwc)
		if err != nil {
			return fmt.Errorf("failed to create attestation key: %v", err)
		}
		defer attestationKey.Close()

		attestOpts := client.AttestOpts{}
		attestOpts.Nonce = nonce
		// Omit requesting TEE attestation for the Attestation message when attesting an SVSM based vTPM.
		// We instead separately attach a TEE attestation inside the SevSnpSvsmAttestation message
		attestOpts.SkipTeeAttestation = true

		attestOpts.TCGEventLog, err = client.GetEventLog(rwc)
		if err != nil {
			return fmt.Errorf("failed to retrieve TCG Event Log: %w", err)
		}

		attestation, err := attestationKey.Attest(attestOpts)
		if err != nil {
			return fmt.Errorf("failed to collect attestation report : %v", err)
		}

		if teeTechnology != SevSnp {
			return errSvsmOnlySupportedWithSevSnp
		}
		configfsClient, err := linuxtsm.MakeClient()
		if err != nil {
			return fmt.Errorf("failed to create linuxtsm configfs client: %w", err)
		}
		svsmAttestation, err := makeSEVSNPSVSMAttestation(attestation, &sevSNPSVSMAttestationOpts{
			TEENonce:                   teeNonce,
			CongfigfsClient:            configfsClient,
			VTPMServiceManifestVersion: "0",
			ExtractOptions:             extract.DefaultOptions(),
		})
		if err != nil {
			return fmt.Errorf("failed to create SEV SNP SVSM attestation: %w", err)
		}
		if err := writeProtoToOutput(svsmAttestation); err != nil {
			return fmt.Errorf("failed to write SEV SNP SVSM attestation report: %w", err)
		}

		return nil
	},
}

// sevSNPSVSMAttestationOpts customizes the behavior of makeSEVSNPSVSMAttestation.
type sevSNPSVSMAttestationOpts struct {
	// 64 byte nonce to be mixed into the REPORT_DATA field of the SNP attestation report.
	TEENonce []byte
	// Configfs client to use for retrieving the attestation report, certificates, and SVSM service manifest.
	CongfigfsClient configfsi.Client
	// The SVSM service manifest and its version is defined by the SVSM spec at
	// https://www.amd.com/en/developer/sev.html
	// Failing to specify a value here will result in requesting the default manifest version of "0"
	// See https://github.com/torvalds/linux/blob/v6.16/Documentation/ABI/testing/configfs-tsm-report
	VTPMServiceManifestVersion string
	// Options for configuring how to extract a firmware endorsement.
	// Leave as nil to skip getting firmware endorsement.
	ExtractOptions *extract.Options
}

// makeSEVSNPSVSMAttestation fills out the fields of a SevSnpSvsmAttestation message needed to verify an SVSM e-vTPM.
// This includes the SNP attestation report and the vtpm service manifest.
func makeSEVSNPSVSMAttestation(attestation *apb.Attestation, opts *sevSNPSVSMAttestationOpts) (*apb.SevSnpSvsmAttestation, error) {
	svsm := &apb.SevSnpSvsmAttestation{
		Attestation: attestation,
	}
	var snpNonce [sabi.ReportDataSize]byte
	if len(opts.TEENonce) != sabi.ReportDataSize {
		return nil, fmt.Errorf("the teeNonce size is %d. SEV-SNP device requires 64", len(opts.TEENonce))
	}
	copy(snpNonce[:], opts.TEENonce)

	// There is a host ratelimit of 2 requests per 2 seconds on guest message requests
	// and SVSM will decide to crash if it runs into this ratelimit.
	// Until we fix this in Coconut SVSM and increase the host ratelimit, ensure a 2
	// second delay prior to issuing an attestation report request to SVSM.
	time.Sleep(2 * time.Second)
	tsmBlobs, err := getSVSMBlobs(opts.CongfigfsClient, snpNonce, opts.VTPMServiceManifestVersion)
	if err != nil {
		return nil, fmt.Errorf("failed to get configfs-tsm blobs for SVSM attestation report: %w", err)
	}
	report, err := sabi.ReportToProto(tsmBlobs.OutBlob)
	if err != nil {
		return nil, fmt.Errorf("failed to convert attestation report to proto: %w", err)
	}

	certs, err := getCertificates(opts.CongfigfsClient, snpNonce)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve certificates from configfs-tsm: %w", err)
	}

	svsm.SevSnpAttestation = &sevpb.Attestation{
		Report:           report,
		CertificateChain: certs,
	}
	svsm.VtpmServiceManifest = tsmBlobs.ManifestBlob
	if opts.VTPMServiceManifestVersion == "" {
		svsm.VtpmServiceManifestVersion = defaultConfigfsTsmReportServiceManifestVersion
	}
	svsm.VtpmServiceManifestVersion = opts.VTPMServiceManifestVersion

	if opts.ExtractOptions != nil {
		svsm.LaunchEndorsement, err = getEndorsement(svsm.SevSnpAttestation, opts.ExtractOptions)
		if err != nil {
			return nil, fmt.Errorf("failed to get endorsement for svsm firmware: %w", err)
		}
	}
	return svsm, nil
}

func getEndorsement(attestation *sevpb.Attestation, extractOpts *extract.Options) ([]byte, error) {
	if extractOpts == nil {
		return nil, nil
	}
	out, err := proto.Marshal(attestation)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal sev snp attestation: %w", err)
	}
	extractOpts.Quote = out
	return extract.Endorsement(extractOpts)
}

// Constants for input to various blobs of configfs-tsm-report defined by linux kernel.
// See https://github.com/torvalds/linux/blob/v6.16/Documentation/ABI/testing/configfs-tsm-report
const (
	svsmServiceProvider = "svsm"
	// GUID for SVSM vTPM attestation defined by SVSM spec.
	// See https://www.amd.com/en/developer/sev.html for SVSM spec
	svsmVTPMServiceGUID                            = "c476f1eb-0123-45a5-9641-b4e7dde5bfe3"
	leastPrivilegedVMPL                            = 3
	defaultConfigfsTsmReportServiceManifestVersion = "0"
)

var (
	errFailedToRetrieveCertificates = errors.New("failed to retrieve certificates")
)

// SVSM currently doesn't support certificates in its attestation report, so here we collect
// the certificate chain by requesting a report without SVSM to get the cached certificates.
func getCertificates(configfs configfsi.Client, reportData [sabi.ReportDataSize]byte) (*sevpb.CertificateChain, error) {
	resp, err := report.Get(configfs, &report.Request{
		InBlob:     reportData[:],
		GetAuxBlob: true,
		Privilege: &report.Privilege{
			Level: uint(leastPrivilegedVMPL),
		},
	})
	if err != nil {
		return nil, errFailedToRetrieveCertificates
	}
	extended, err := sabi.ExtendedPlatformCertTable(resp.AuxBlob)
	if err != nil {
		return nil, fmt.Errorf("invalid certificate table: %w", err)
	}
	table := new(sabi.CertTable)
	if err := table.Unmarshal(extended); err != nil {
		return nil, fmt.Errorf("failed to unmarshal certificates: %w", err)
	}
	return table.Proto(), nil
}

func getSVSMBlobs(configfs configfsi.Client, reportData [sabi.ReportDataSize]byte, vtpmServiceManifestVersion string) (*report.Response, error) {
	resp, err := report.Get(configfs, &report.Request{
		InBlob:                 reportData[:],
		ServiceProvider:        svsmServiceProvider,
		ServiceGuid:            svsmVTPMServiceGUID,
		ServiceManifestVersion: vtpmServiceManifestVersion,
	})
	if err != nil {
		return nil, fmt.Errorf("could not get SVSM attestation report: %w", err)
	}
	return resp, nil
}
