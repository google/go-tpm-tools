package device

import (
	"errors"
	"testing"

	"github.com/google/go-cmp/cmp"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"

	attestationpb "github.com/GoogleCloudPlatform/confidential-space/server/proto/gen/attestation"
	gecel "github.com/google/go-eventlog/cel"
	"github.com/google/go-tpm-tools/cel"
)

type fakeROT struct {
	vendor        Vendor
	attestResp    any
	attestErr     error
	readyStateErr error
	enabled       bool
}

func (f *fakeROT) Vendor() Vendor {
	return f.vendor
}

func (f *fakeROT) Attest(_ []byte) (any, error) {
	if f.attestErr != nil {
		return nil, f.attestErr
	}
	return f.attestResp, nil
}

func (f *fakeROT) EnableReadyState() error {
	if f.readyStateErr != nil {
		return f.readyStateErr
	}
	f.enabled = true
	return nil
}

type fakeMeasurer struct {
	measuredEvents []gecel.Content
	measureErr     error
}

func (f *fakeMeasurer) MeasureEvent(event gecel.Content) error {
	if f.measureErr != nil {
		return f.measureErr
	}
	f.measuredEvents = append(f.measuredEvents, event)
	return nil
}

func TestAttestDeviceROTs(t *testing.T) {
	sampleReport := &attestationpb.NvidiaAttestationReport{
		CcFeature: &attestationpb.NvidiaAttestationReport_Spt{
			Spt: &attestationpb.NvidiaAttestationReport_SinglePassthroughAttestation{},
		},
	}

	testCases := []struct {
		name        string
		rots        []ROT
		opts        ReportOpts
		wantReports []any
		wantErr     bool
	}{
		{
			name: "Nvidia GPU with runtime attestation enabled",
			rots: []ROT{
				&fakeROT{
					vendor:     NvidiaGPU,
					attestResp: sampleReport,
				},
			},
			opts:        ReportOpts{EnableRuntimeGPUAttestation: true},
			wantReports: []any{sampleReport},
		},
		{
			name: "Multiple same ROT vendors with runtime GPU attestation enabled",
			rots: []ROT{
				&fakeROT{
					vendor:     NvidiaGPU,
					attestResp: sampleReport,
				},
				&fakeROT{
					vendor:     NvidiaGPU,
					attestResp: sampleReport,
				},
			},
			opts:        ReportOpts{EnableRuntimeGPUAttestation: true},
			wantReports: []any{sampleReport, sampleReport},
		},
		{
			name: "Nvidia GPU with runtime attestation disabled",
			rots: []ROT{
				&fakeROT{
					vendor:     NvidiaGPU,
					attestResp: sampleReport,
				},
			},
			opts:        ReportOpts{EnableRuntimeGPUAttestation: false},
			wantReports: nil,
		},
		{
			name: "Attest error aggregated",
			rots: []ROT{
				&fakeROT{
					vendor:    NvidiaGPU,
					attestErr: errors.New("gpu failure"),
				},
			},
			opts:    ReportOpts{EnableRuntimeGPUAttestation: true},
			wantErr: true,
		},
		{
			name: "Multiple different ROT vendors with runtime GPU attestation enabled",
			rots: []ROT{
				&fakeROT{
					vendor:     NvidiaGPU,
					attestResp: sampleReport,
				},
				&fakeROT{
					vendor:     Vendor(99),
					attestResp: sampleReport,
				},
			},
			opts:    ReportOpts{EnableRuntimeGPUAttestation: true},
			wantErr: true,
		},
		{
			name: "Multiple different ROT vendors with runtime GPU attestation disabled",
			rots: []ROT{
				&fakeROT{
					vendor:     NvidiaGPU,
					attestResp: sampleReport,
				},
				&fakeROT{
					vendor:     Vendor(99),
					attestResp: sampleReport,
				},
			},
			opts:    ReportOpts{EnableRuntimeGPUAttestation: false},
			wantErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			m := NewROTManager(tc.rots)
			got, err := m.AttestDeviceROTs([]byte("nonce"), tc.opts)
			if (err != nil) != tc.wantErr {
				t.Fatalf("AttestDeviceROTs() error = %v, wantErr %v", err, tc.wantErr)
			}
			if tc.wantErr {
				return
			}
			if diff := cmp.Diff(tc.wantReports, got, protocmp.Transform()); diff != "" {
				t.Errorf("AttestDeviceROTs() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestMeasureDeviceEvidence(t *testing.T) {
	sampleReport := &attestationpb.NvidiaAttestationReport{
		CcFeature: &attestationpb.NvidiaAttestationReport_Spt{
			Spt: &attestationpb.NvidiaAttestationReport_SinglePassthroughAttestation{},
		},
	}
	sampleBytes, err := proto.Marshal(sampleReport)
	if err != nil {
		t.Fatalf("failed to marshal sampleReport: %v", err)
	}

	testCases := []struct {
		name        string
		rots        []ROT
		measurer    *fakeMeasurer
		wantEvents  []gecel.Content
		wantEnabled bool
		wantErr     bool
	}{
		{
			name: "Success Nvidia GPU",
			rots: []ROT{
				&fakeROT{
					vendor:     NvidiaGPU,
					attestResp: sampleReport,
				},
			},
			measurer: &fakeMeasurer{},
			wantEvents: []gecel.Content{
				cel.CosTlv{
					EventType:    cel.GPUDeviceAttestationBindingType,
					EventContent: sampleBytes,
				},
			},
			wantEnabled: true,
		},
		{
			name: "Attest error",
			rots: []ROT{
				&fakeROT{
					vendor:    NvidiaGPU,
					attestErr: errors.New("attest failed"),
				},
			},
			measurer: &fakeMeasurer{},
			wantErr:  true,
		},
		{
			name: "Measure error",
			rots: []ROT{
				&fakeROT{
					vendor:     NvidiaGPU,
					attestResp: sampleReport,
				},
			},
			measurer: &fakeMeasurer{measureErr: errors.New("measure failed")},
			wantErr:  true,
		},
		{
			name: "EnableReadyState error",
			rots: []ROT{
				&fakeROT{
					vendor:        NvidiaGPU,
					attestResp:    sampleReport,
					readyStateErr: errors.New("enable failed"),
				},
			},
			measurer: &fakeMeasurer{},
			wantErr:  true,
		},
		{
			name: "Multiple different ROT vendors error",
			rots: []ROT{
				&fakeROT{
					vendor:     NvidiaGPU,
					attestResp: sampleReport,
				},
				&fakeROT{
					vendor:     Vendor(99),
					attestResp: sampleReport,
				},
			},
			measurer: &fakeMeasurer{},
			wantErr:  true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			m := NewROTManager(tc.rots)
			err := m.MeasureDeviceEvidence([]byte("nonce"), tc.measurer)
			if (err != nil) != tc.wantErr {
				t.Fatalf("MeasureDeviceEvidence() error = %v, wantErr %v", err, tc.wantErr)
			}
			if tc.wantErr {
				return
			}
			if diff := cmp.Diff(tc.wantEvents, tc.measurer.measuredEvents); diff != "" {
				t.Errorf("Measured events mismatch (-want +got):\n%s", diff)
			}
			for _, rot := range tc.rots {
				fake := rot.(*fakeROT)
				if fake.enabled != tc.wantEnabled {
					t.Errorf("rot enabled = %v, want %v", fake.enabled, tc.wantEnabled)
				}
			}
		})
	}
}
