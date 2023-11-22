package systemctl

import (
	"context"
	"errors"
	"testing"
)

func TestRunSystmedCmd(t *testing.T) {
	doneUnitFunc := func(ctx context.Context, unit string, mode string, progress chan<- string) (int, error) {
		progress <- "done"
		return 1, nil
	}
	failedCallUnitFunc := func(ctx context.Context, unit string, mode string, progress chan<- string) (int, error) {
		return 1, errors.New("something went wrong")
	}
	failedUnitFunc := func(ctx context.Context, unit string, mode string, progress chan<- string) (int, error) {
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
