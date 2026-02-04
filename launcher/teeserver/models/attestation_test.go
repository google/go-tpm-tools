package models

import (
	"encoding/json"
	"testing"

	"github.com/google/go-cmp/cmp"
	attestpb "github.com/google/go-tpm-tools/proto/attest"
	tpmpb "github.com/google/go-tpm-tools/proto/tpm"
	"google.golang.org/protobuf/testing/protocmp"
)

func TestCVMAttestationMarshaling(t *testing.T) {
	tests := []struct {
		name string
		in   *CVMAttestation
	}{
		{
			name: "TDX Attestation",
			in: &CVMAttestation{
				Label:     []byte("test-label"),
				Challenge: []byte("test-challenge"),
				Attestation: &CVMAttestationQuote{
					TDXAttestation: &TDXCCELAttestation{
						CCELBootEventLog:  []byte("ccel-data"),
						CELLaunchEventLog: []byte("cel-data"),
						TDQuote:           []byte("td-quote"),
					},
					DeviceReports: []DeviceAttestationReport{{}},
				},
			},
		},
		{
			name: "TPM Attestation",
			in: &CVMAttestation{
				Label:     []byte("test-label-tpm"),
				Challenge: []byte("test-challenge-tpm"),
				Attestation: &CVMAttestationQuote{
					TPMAttestation: &attestpb.Attestation{
						AkPub: []byte("ak-pub"),
						Quotes: []*tpmpb.Quote{
							{
								Quote: []byte("quote-bytes"),
							},
						},
					},
				},
			},
		},
		{
			name: "Empty",
			in:   &CVMAttestation{},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			blob, err := json.Marshal(tc.in)
			if err != nil {
				t.Fatalf("Failed to marshal: %v", err)
			}

			var out CVMAttestation
			if err := json.Unmarshal(blob, &out); err != nil {
				t.Fatalf("Failed to unmarshal: %v", err)
			}

			if diff := cmp.Diff(tc.in, &out, protocmp.Transform()); diff != "" {
				t.Errorf("Marshaling roundtrip mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
