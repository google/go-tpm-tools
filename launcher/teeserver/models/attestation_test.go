package models

import (
	"encoding/json"
	"testing"

	"github.com/google/go-cmp/cmp"
	attestpb "github.com/google/go-tpm-tools/proto/attest"
	tpmpb "github.com/google/go-tpm-tools/proto/tpm"
	"google.golang.org/protobuf/testing/protocmp"
)

func TestVMAttestationMarshaling(t *testing.T) {
	tests := []struct {
		name string
		in   *VMAttestation
		want string
	}{
		{
			name: "TDX Attestation",
			in: &VMAttestation{
				Label:     []byte("test-label"),
				Challenge: []byte("test-challenge"),
				ExtraData: []byte("test-extra"),
				Quote: &VMAttestationQuote{
					TDXCCELQuote: &TDXCCELQuote{
						CCELBootEventLog:  []byte("ccel-data"),
						CELLaunchEventLog: []byte("cel-data"),
						TDQuote:           []byte("td-quote"),
					},
				},
				DeviceReports: []DeviceAttestationReport{{}},
			},
			want: `{"label":"dGVzdC1sYWJlbA==","challenge":"dGVzdC1jaGFsbGVuZ2U=","extra_data":"dGVzdC1leHRyYQ==","vm_attestation_quote":{"tdx_ccel_quote":{"ccel_boot_event_log":"Y2NlbC1kYXRh","cel_launch_event_log":"Y2VsLWRhdGE=","td_quote":"dGQtcXVvdGU="}},"device_reports":[{}]}`,
		},
		{
			name: "TPM Attestation",
			in: &VMAttestation{
				Label:     []byte("test-label-tpm"),
				Challenge: []byte("test-challenge-tpm"),
				Quote: &VMAttestationQuote{
					VTPMAttestation: &attestpb.Attestation{
						AkPub: []byte("ak-pub"),
						Quotes: []*tpmpb.Quote{
							{
								Quote: []byte("quote-bytes"),
							},
						},
					},
				},
			},
			want: `{"label":"dGVzdC1sYWJlbC10cG0=","challenge":"dGVzdC1jaGFsbGVuZ2UtdHBt","vm_attestation_quote":{"vtpm_attestation":{"quotes":[{"quote":"cXVvdGUtYnl0ZXM="}],"ak_pub":"YWstcHVi","TeeAttestation":null}}}`,
		},
		{
			name: "Empty Quote",
			in: &VMAttestation{
				Label:     []byte("label"),
				Challenge: []byte("challenge"),
				Quote:     &VMAttestationQuote{},
			},
			want: `{"label":"bGFiZWw=","challenge":"Y2hhbGxlbmdl","vm_attestation_quote":{}}`,
		},
		{
			name: "Empty",
			in:   &VMAttestation{},
			want: `{"label":null,"challenge":null,"vm_attestation_quote":null}`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			blob, err := json.Marshal(tc.in)
			if err != nil {
				t.Fatalf("Failed to marshal: %v", err)
			}

			var out VMAttestation
			if err := json.Unmarshal(blob, &out); err != nil {
				t.Fatalf("Failed to unmarshal: %v", err)
			}

			if diff := cmp.Diff(tc.in, &out, protocmp.Transform()); diff != "" {
				t.Errorf("Marshaling roundtrip mismatch (-want +got):\n%s", diff)
			}

			// 2. Check the JSON string output matches our expectation
			if tc.want != "" {
				// Unmarshal both into map[string]any to ignore key ordering and formatting
				var gotMap map[string]any
				if err := json.Unmarshal(blob, &gotMap); err != nil {
					t.Fatalf("Failed to unmarshal got JSON: %v", err)
				}

				var wantMap map[string]any
				if err := json.Unmarshal([]byte(tc.want), &wantMap); err != nil {
					t.Fatalf("Failed to unmarshal want JSON: %v", err)
				}

				if diff := cmp.Diff(wantMap, gotMap); diff != "" {
					t.Errorf("JSON mismatch (-want +got):\n%s", diff)
				}
			}
		})
	}
}
