package device

import (
	"errors"
	"testing"

	"github.com/google/go-cmp/cmp"
	"go.uber.org/multierr"
)

type mockROT struct {
	vendor Vendor
	report any
	err    error
}

func (m *mockROT) Attest(_ []byte) (any, error) {
	return m.report, m.err
}

func (m *mockROT) Vendor() Vendor {
	return m.vendor
}

func TestAttestDeviceROTs(t *testing.T) {
	testCases := []struct {
		name         string
		rots         []ROT
		opts         ReportOpts
		wantReports  []any
		wantErr      bool
		wantErrCount int
	}{
		{
			name: "NvidiaGPU with runtime attestation enabled",
			rots: []ROT{
				&mockROT{vendor: NvidiaGPU, report: "gpu-report"},
			},
			opts:        ReportOpts{EnableRuntimeGPUAttestation: true},
			wantReports: []any{"gpu-report"},
			wantErr:     false,
		},
		{
			name: "NvidiaGPU with runtime attestation disabled",
			rots: []ROT{
				&mockROT{vendor: NvidiaGPU, report: "gpu-report"},
			},
			opts:        ReportOpts{EnableRuntimeGPUAttestation: false},
			wantReports: nil,
			wantErr:     false,
		},
		{
			name: "Unspecified vendor is ignored",
			rots: []ROT{
				&mockROT{vendor: Unspecified, report: "some-report"},
			},
			opts:        ReportOpts{EnableRuntimeGPUAttestation: true},
			wantReports: nil,
			wantErr:     false,
		},
		{
			name: "Multiple devices, one fails",
			rots: []ROT{
				&mockROT{vendor: NvidiaGPU, report: "gpu-report-1"},
				&mockROT{vendor: NvidiaGPU, err: errors.New("attestation failed")},
			},
			opts:         ReportOpts{EnableRuntimeGPUAttestation: true},
			wantReports:  []any{"gpu-report-1"},
			wantErr:      true,
			wantErrCount: 1,
		},
		{
			name: "Multiple devices, multiple fail",
			rots: []ROT{
				&mockROT{vendor: NvidiaGPU, err: errors.New("error 1")},
				&mockROT{vendor: NvidiaGPU, err: errors.New("error 2")},
			},
			opts:         ReportOpts{EnableRuntimeGPUAttestation: true},
			wantReports:  nil,
			wantErr:      true,
			wantErrCount: 2,
		},
		{
			name: "Multiple devices, both succeed",
			rots: []ROT{
				&mockROT{vendor: NvidiaGPU, report: "gpu-report-1"},
				&mockROT{vendor: NvidiaGPU, report: "gpu-report-2"},
			},
			opts:        ReportOpts{EnableRuntimeGPUAttestation: true},
			wantReports: []any{"gpu-report-1", "gpu-report-2"},
			wantErr:     false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			m := NewROTManager(tc.rots)
			gotReports, err := m.AttestDeviceROTs([]byte("nonce"), tc.opts)
			if (err != nil) != tc.wantErr {
				t.Errorf("AttestDeviceROTs() error = %v, wantErr %v", err, tc.wantErr)
				return
			}
			if tc.wantErr {
				errs := multierr.Errors(err)
				if len(errs) != tc.wantErrCount {
					t.Errorf("AttestDeviceROTs() error count = %d, want %d", len(errs), tc.wantErrCount)
				}
			}
			if !cmp.Equal(gotReports, tc.wantReports) {
				t.Errorf("AttestDeviceROTs() gotReports = %v, want %v", gotReports, tc.wantReports)
			}
		})
	}
}

func TestAttestDeviceROTsRace(t *testing.T) {
	rots := []ROT{
		&mockROT{vendor: NvidiaGPU, report: "gpu-report-1"},
		&mockROT{vendor: NvidiaGPU, report: "gpu-report-2"},
	}
	m := NewROTManager(rots)
	opts := ReportOpts{EnableRuntimeGPUAttestation: true}
	nonce := []byte("nonce")

	const numGoroutines = 10
	errCh := make(chan error, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func() {
			reports, err := m.AttestDeviceROTs(nonce, opts)
			if err != nil {
				errCh <- err
				return
			}
			if len(reports) != 2 {
				errCh <- errors.New("unexpected number of reports")
				return
			}
			errCh <- nil
		}()
	}

	for i := 0; i < numGoroutines; i++ {
		if err := <-errCh; err != nil {
			t.Errorf("Race test failure: %v", err)
		}
	}
}
