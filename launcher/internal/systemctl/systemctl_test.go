package systemctl

import (
	"context"
	"errors"
	"testing"
)

func TestRunSystmedCmd(t *testing.T) {
	doneUnitFunc := func(_ context.Context, _, _ string, progress chan<- string) (int, error) {
		progress <- "done"
		return 1, nil
	}
	failedCallUnitFunc := func(context.Context, string, string, chan<- string) (int, error) {
		return 1, errors.New("something went wrong")
	}
	failedUnitFunc := func(_ context.Context, _, _ string, progress chan<- string) (int, error) {
		progress <- "failed"
		return 1, nil
	}

	testCases := []struct {
		name          string
		sytemdCmdFunc func(ctx context.Context, unit string, flag string, progress chan<- string) (int, error)
		wantErr       bool
	}{
		{
			name:          "success",
			sytemdCmdFunc: doneUnitFunc,
			wantErr:       false,
		},
		{
			name:          "failed call",
			sytemdCmdFunc: failedCallUnitFunc,
			wantErr:       true,
		},
		{
			name:          "failed unit run",
			sytemdCmdFunc: failedUnitFunc,
			wantErr:       true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if err := runSystemdCmd(tc.sytemdCmdFunc, "test", "test_unit"); (err != nil) != tc.wantErr {
				t.Errorf("runSystemdCmd() did not return expected error, got error: %v, but wantErr %v", err, tc.wantErr)
			}
		})
	}
}

// TestGetStatus reads the `-.mount` which should exist on all systemd
// systems and ensures that one of its properties is valid.
func TestGetStatus(t *testing.T) {
	systemctl, err := New()
	if err != nil {
		t.Skipf("Failed to create systemctl client: %v", err)
	}

	t.Cleanup(systemctl.Close)

	testCases := []struct {
		name string
		unit string
		want string
	}{
		{
			name: "success",
			unit: "-.mount", //`-.mount` which should exist on all systemd systems,
			want: "active",
		},
		{
			name: "success with an inactive unit",
			unit: "node-problem-detector.service",
			want: "inactive",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := systemctl.IsActive(context.Background(), tc.unit)
			if err != nil {
				t.Fatalf("failed to read status for unit [%s]: %v", tc.unit, got)
			}
			if got != tc.want {
				t.Errorf("GetStatus returned unexpected status for unit [%s], got %s, but want %s", tc.unit, got, tc.want)
			}
		})
	}
}
