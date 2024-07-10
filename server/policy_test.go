package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"math/rand"
	"os"
	"path"
	"strings"
	"testing"
	"time"

	gcesev "github.com/google/gce-tcb-verifier/sev"
	"github.com/google/gce-tcb-verifier/testing/devkeys"
	"github.com/google/gce-tcb-verifier/testing/fakeovmf"
	"github.com/google/gce-tcb-verifier/testing/nonprod"
	spb "github.com/google/go-sev-guest/proto/sevsnp"
	stest "github.com/google/go-sev-guest/testing"
	pb "github.com/google/go-tpm-tools/proto/attest"
)

var defaultGcePolicy = pb.Policy{
	Platform: &pb.PlatformPolicy{
		MinimumGceFirmwareVersion: 1,
		MinimumTechnology:         pb.GCEConfidentialTechnology_NONE,
	},
}

func TestNilPolicyAlwaysPasses(t *testing.T) {
	subtests := []struct {
		name  string
		state *pb.MachineState
	}{
		{"NilState", nil},
		{"PlatformState", &pb.MachineState{
			Platform: &pb.PlatformState{
				Firmware:   &pb.PlatformState_GceVersion{GceVersion: 1},
				Technology: pb.GCEConfidentialTechnology_AMD_SEV,
			},
		}},
	}
	for _, subtest := range subtests {
		t.Run(subtest.name, func(t *testing.T) {
			if err := EvaluatePolicy(subtest.state, nil); err != nil {
				t.Errorf("nil policy should always succeed: %v", err)
			}
		})
	}
}

func TestGCEFirmwareVersionSimple(t *testing.T) {
	zero := ConvertGCEFirmwareVersionToSCRTMVersion(0)
	if len(zero) != 0 {
		t.Errorf("expected empty SCRTM version, got %x", zero)
	}
	ver, err := ConvertSCRTMVersionToGCEFirmwareVersion(
		ConvertGCEFirmwareVersionToSCRTMVersion(23),
	)
	if ver != 23 {
		t.Errorf("convert functions aren't inverses, got %d: %v", ver, err)
	}
}

func TestEvaluatePolicy(t *testing.T) {
	tests := []struct {
		name   string
		log    eventLog
		policy *pb.Policy
	}{
		{"Debian10-SHA1", Debian10GCE, &defaultGcePolicy},
		{"RHEL8-CryptoAgile", Rhel8GCE, &defaultGcePolicy},
		{"Ubuntu1804AmdSev-CryptoAgile", UbuntuAmdSevGCE, &defaultGcePolicy},
		// TODO: add the tests below back once go-attestation has releases:
		// https://github.com/google/go-attestation/pull/222/
		// {"Ubuntu2104NoDbx-CryptoAgile", Ubuntu2104NoDbxGCE, &defaultGcePolicy},
		// {"Ubuntu2104NoSecureBoot-CryptoAgile", Ubuntu2104NoSecureBootGCE, &defaultGcePolicy},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			machineState, err := parsePCClientEventLog(test.log.RawLog, test.log.Banks[0], UnsupportedLoader)
			if err != nil {
				t.Fatalf("failed to get machine state: %v", err)
			}
			if err := EvaluatePolicy(machineState, test.policy); err != nil {
				t.Errorf("failed to apply policy: %v", err)
			}
		})
	}
}

func TestEvaluatePolicySCRTM(t *testing.T) {
	archLinuxWorkstationSCRTMPolicy := pb.Policy{
		Platform: &pb.PlatformPolicy{
			AllowedScrtmVersionIds: [][]byte{{0x1e, 0xfb, 0x6b, 0x54, 0x0c, 0x1d, 0x55, 0x40, 0xa4, 0xad,
				0x4e, 0xf4, 0xbf, 0x17, 0xb8, 0x3a}},
		},
	}
	machineState, err := parsePCClientEventLog(ArchLinuxWorkstation.RawLog, ArchLinuxWorkstation.Banks[0], UnsupportedLoader)
	if err != nil {
		gErr := err.(*GroupedError)
		if !gErr.containsKnownSubstrings(archLinuxKnownParsingFailures) {
			t.Fatalf("failed to get machine state: %v", err)
		}
	}
	if err := EvaluatePolicy(machineState, &archLinuxWorkstationSCRTMPolicy); err != nil {
		t.Errorf("failed to apply policy: %v", err)
	}
}

func TestEvaluatePolicyFailure(t *testing.T) {
	badGcePolicyVersion := pb.Policy{
		Platform: &pb.PlatformPolicy{
			MinimumGceFirmwareVersion: 2,
			MinimumTechnology:         pb.GCEConfidentialTechnology_NONE,
		},
	}
	badGcePolicySEVES := pb.Policy{
		Platform: &pb.PlatformPolicy{
			MinimumGceFirmwareVersion: 0,
			MinimumTechnology:         pb.GCEConfidentialTechnology_AMD_SEV_ES,
		},
	}
	badGcePolicySEV := pb.Policy{
		Platform: &pb.PlatformPolicy{
			MinimumGceFirmwareVersion: 0,
			MinimumTechnology:         pb.GCEConfidentialTechnology_AMD_SEV_ES,
		},
	}
	badPhysicalPolicy := pb.Policy{
		Platform: &pb.PlatformPolicy{
			AllowedScrtmVersionIds: [][]byte{{0x00}},
		},
	}
	tests := []struct {
		name   string
		log    eventLog
		policy *pb.Policy
		// This field handles known issues with event log parsing or bad event
		// logs.
		// Set to nil when the event log has no known issues.
		errorSubstrs []string
	}{
		{"Debian10-SHA1", Debian10GCE, &badGcePolicyVersion, nil},
		{"Debian10-SHA1", Debian10GCE, &badGcePolicySEV, nil},
		{"Ubuntu1804AmdSev-CryptoAgile", UbuntuAmdSevGCE, &badGcePolicySEVES,
			nil},
		{"ArchLinuxWorkstation-CryptoAgile", ArchLinuxWorkstation,
			&badPhysicalPolicy, archLinuxKnownParsingFailures},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			machineState, err := parsePCClientEventLog(test.log.RawLog, test.log.Banks[0], UnsupportedLoader)
			if err != nil {
				gErr := err.(*GroupedError)
				if len(test.errorSubstrs) == 0 || !gErr.containsKnownSubstrings(test.errorSubstrs) {
					t.Fatalf("failed to get machine state: %v", err)
				}
			}
			if err := EvaluatePolicy(machineState, test.policy); err == nil {
				t.Errorf("expected policy failure; got success")
			}
		})
	}
}

func TestSevSnpSignedUefi(t *testing.T) {
	// Generate fake signed reference measurements.
	fw := fakeovmf.CleanExample(t, 0x200000)
	meas, err := gcesev.LaunchDigest(gcesev.LaunchOptionsDefault(), fw)
	if err != nil {
		t.Fatal(err)
	}
	certdir := t.TempDir()
	keydir := t.TempDir()
	outdir := t.TempDir()
	if err := devkeys.DumpTo(&devkeys.Options{
		KeyDir:   keydir,
		CertRoot: certdir,
		CertDir:  "signer_certs",
		Bucket:   "certs-dev",
	}); err != nil {
		t.Fatal(err)
	}
	fwdir := t.TempDir()
	fwPath := path.Join(fwdir, "fw.fd")
	if err := os.WriteFile(fwPath, fw, 0666); err != nil {
		t.Fatal(err)
	}

	nonprod.RootCmd.SetArgs([]string{"endorse",
		"--uefi", fwPath,
		"--key_dir", keydir,
		"--bucket_root", certdir,
		"--root_path", "root.crt",
		"--add_snp",
		"--out_root", outdir,
		"--snapshot_dir", "snap",
	})
	if err := nonprod.RootCmd.Execute(); err != nil {
		t.Fatal(err)
	}
	rim, err := os.ReadFile(path.Join(outdir, "snap", "fw.fd.signed"))
	if err != nil {
		t.Fatalf("endorsement missing: %v", err)
	}

	// Generate fake VCEK certificate that can pass the basic validation checks.
	block, _ := pem.Decode(devkeys.RootPEM)
	pregenRoot, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	block, _ = pem.Decode(devkeys.RootCert)
	rootDER := block.Bytes
	insecureRandomness := rand.New(rand.NewSource(0xc0de))
	vcek, err := ecdsa.GenerateKey(elliptic.P384(), insecureRandomness)
	if err != nil {
		t.Fatalf("could not generate fake VCEK: %v", err)
	}
	b := stest.AmdSignerBuilder{
		Keys: &stest.AmdKeys{
			Ark:  pregenRoot.(*rsa.PrivateKey),
			Ask:  pregenRoot.(*rsa.PrivateKey),
			Asvk: pregenRoot.(*rsa.PrivateKey),
			Vcek: vcek,
		},
	}
	signer, _ := b.TestOnlyCertChain()
	vcekCert := signer.Vcek.Raw

	disconnected := &PolicyOptions{Now: time.Now(), Getter: &stest.Getter{}}
	nogetter := &PolicyOptions{Now: time.Now()}
	tcs := []struct {
		name    string
		ms      *pb.MachineState
		pol     *pb.Policy
		wantErr string
		opts    *PolicyOptions
	}{
		{
			name: "happy path disconnected",
			ms: &pb.MachineState{
				TeeAttestation: &pb.MachineState_SevSnpAttestation{
					SevSnpAttestation: &spb.Attestation{
						Report: &spb.Report{
							Policy:      0x20000,
							Measurement: meas,
						},
						CertificateChain: &spb.CertificateChain{
							VcekCert: vcekCert,
							Extras: map[string][]byte{
								gcesev.GCEFwCertGUID: rim,
							},
						},
					},
				},
			},
			pol: &pb.Policy{
				SevSnp: &pb.SevSnpPolicy{
					Uefi: &pb.RIMPolicy{
						RootCerts: [][]byte{rootDER},
					},
				},
			},
			opts: disconnected,
		},
		{
			name: "optional, no getter",
			ms: &pb.MachineState{
				TeeAttestation: &pb.MachineState_SevSnpAttestation{
					SevSnpAttestation: &spb.Attestation{
						Report: &spb.Report{
							Policy:      0x20000,
							Measurement: meas,
						},
						CertificateChain: &spb.CertificateChain{
							VcekCert: vcekCert,
						},
					},
				},
			},
			pol: &pb.Policy{
				SevSnp: &pb.SevSnpPolicy{
					Uefi: &pb.RIMPolicy{
						RequireSigned: true,
						RootCerts:     [][]byte{rootDER},
					},
				},
			},
			opts:    nogetter,
			wantErr: "endorsement getter is nil",
		},
		{
			name: "happy path required, disconnected",
			ms: &pb.MachineState{
				TeeAttestation: &pb.MachineState_SevSnpAttestation{
					SevSnpAttestation: &spb.Attestation{
						Report: &spb.Report{
							Policy:      0x20000,
							Measurement: meas,
						},
						CertificateChain: &spb.CertificateChain{
							VcekCert: vcekCert,
							Extras: map[string][]byte{
								gcesev.GCEFwCertGUID: rim,
							},
						},
					},
				},
			},
			pol: &pb.Policy{
				SevSnp: &pb.SevSnpPolicy{
					Uefi: &pb.RIMPolicy{
						RequireSigned: true,
						RootCerts:     [][]byte{rootDER},
					},
				},
			},
			opts: disconnected,
		},
		{
			name: "required, disconnected",
			ms: &pb.MachineState{
				TeeAttestation: &pb.MachineState_SevSnpAttestation{
					SevSnpAttestation: &spb.Attestation{
						Report: &spb.Report{
							Policy:      0x20000,
							Measurement: meas,
						},
						CertificateChain: &spb.CertificateChain{
							VcekCert: vcekCert,
						},
					},
				},
			},
			pol: &pb.Policy{
				SevSnp: &pb.SevSnpPolicy{
					Uefi: &pb.RIMPolicy{
						RequireSigned: true,
						RootCerts:     [][]byte{rootDER},
					},
				},
			},
			opts:    disconnected,
			wantErr: "could not fetch endorsement",
		},
		{name: "nil policy quot libet"},
		{
			name: "nil policy empty ms",
			ms:   &pb.MachineState{},
		},
		{
			name: "empty platform policy accepts",
			ms:   &pb.MachineState{},
			pol:  &pb.Policy{Platform: &pb.PlatformPolicy{}},
		},
		{
			name:    "Nil SevSnpAttestation ill-formed",
			ms:      &pb.MachineState{TeeAttestation: &pb.MachineState_SevSnpAttestation{}},
			wantErr: "attestation is nil",
		},
		{
			name: "SevSnpAttestation nil sevsnp policy",
			ms:   &pb.MachineState{TeeAttestation: &pb.MachineState_SevSnpAttestation{SevSnpAttestation: &spb.Attestation{}}},
			pol:  &pb.Policy{},
		},
		{
			name: "SevSnpAttestation empty sevsnp policy",
			ms:   &pb.MachineState{TeeAttestation: &pb.MachineState_SevSnpAttestation{SevSnpAttestation: &spb.Attestation{}}},
			pol:  &pb.Policy{SevSnp: &pb.SevSnpPolicy{}},
		},
		{
			name: "SevSnpAttestation empty uefi policy",
			ms: &pb.MachineState{TeeAttestation: &pb.MachineState_SevSnpAttestation{
				SevSnpAttestation: &spb.Attestation{
					Report:           &spb.Report{},
					CertificateChain: &spb.CertificateChain{},
				}}},
			pol: &pb.Policy{SevSnp: &pb.SevSnpPolicy{Uefi: &pb.RIMPolicy{}}},
			// No root of trust provided for UEFI.
			wantErr: "unsupported key kind VCEK",
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			err := EvaluatePolicyOpt(tc.ms, tc.pol, tc.opts)
			trueSuccess := err == nil && tc.wantErr == ""
			trueError := err != nil && tc.wantErr != "" && strings.Contains(err.Error(), tc.wantErr)
			if !trueSuccess && !trueError {
				t.Fatalf("EvaluatePolicy(%v, %v) = %v, want %q", tc.ms, tc.pol, err, tc.wantErr)
			}
		})
	}
}
