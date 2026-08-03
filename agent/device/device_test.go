package device

import (
	"errors"
	"testing"

	"github.com/google/go-cmp/cmp"
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

func TestAttestDeviceROTs(t *testing.T) {
	sampleReport := "sample-report"

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
			opts:        ReportOpts{EnableRuntimeGPUAttestation: true},
			wantReports: []any{sampleReport},
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
			opts:        ReportOpts{EnableRuntimeGPUAttestation: false},
			wantReports: nil,
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
			if diff := cmp.Diff(tc.wantReports, got); diff != "" {
				t.Errorf("AttestDeviceROTs() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestROTManager_Lookup(t *testing.T) {
	rot1 := &fakeROT{vendor: NvidiaGPU}
	rot2 := &fakeROT{vendor: NvidiaGPU}
	rot3 := &fakeROT{vendor: Vendor(99)}

	m := NewROTManager([]ROT{rot1, rot2, rot3})
	gpus := m.Lookup(NvidiaGPU)
	if len(gpus) != 2 {
		t.Fatalf("expected 2 NvidiaGPU ROTs, got %d", len(gpus))
	}
	others := m.Lookup(Vendor(99))
	if len(others) != 1 {
		t.Fatalf("expected 1 Vendor(99) ROT, got %d", len(others))
	}
	none := m.Lookup(Unspecified)
	if len(none) != 0 {
		t.Fatalf("expected 0 Unspecified ROTs, got %d", len(none))
	}
}

func TestROTManager_ValidateROTs(t *testing.T) {
	rot1 := &fakeROT{vendor: NvidiaGPU}
	rot2 := &fakeROT{vendor: Vendor(99)}

	m := NewROTManager([]ROT{rot1, rot2})
	if err := m.ValidateROTs(); err != nil {
		t.Fatalf("expected ValidateROTs to succeed with multiple vendors, got %v", err)
	}
}
