package gpumanager

import (
	"context"
	"errors"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	gpumanagerpb "github.com/GoogleCloudPlatform/confidential-space/server/proto/gen/gpumanager"
	"google.golang.org/grpc"
)

type testLogger struct {
	warns []string
}

func (l *testLogger) Info(string, ...any)       {}
func (l *testLogger) Warn(msg string, _ ...any) { l.warns = append(l.warns, msg) }

// step is one scripted GetHealthz result.
type step struct {
	resp *gpumanagerpb.GetHealthzResponse
	err  error
}

// scripted returns a healthzFunc that returns each step in turn and repeats
// the last one, plus a pointer to the number of calls made.
func scripted(steps ...step) (healthzFunc, *int) {
	calls := 0
	return func(context.Context) (*gpumanagerpb.GetHealthzResponse, error) {
		s := steps[min(calls, len(steps)-1)]
		calls++
		return s.resp, s.err
	}, &calls
}

func healthStep(s gpumanagerpb.HealthState, msg string) step {
	return step{resp: &gpumanagerpb.GetHealthzResponse{HealthState: s, ErrorMessage: msg}}
}

func TestWaitForReady(t *testing.T) {
	unavailable := step{err: errors.New("connection refused")}
	testCases := []struct {
		name       string
		steps      []step
		wantErr    string
		wantErrIs  error
		wantCalls  int
		wantWarned bool
	}{
		{
			name:      "ready immediately",
			steps:     []step{healthStep(gpumanagerpb.HealthState_HEALTH_STATE_READY, "")},
			wantCalls: 1,
		},
		{
			name: "socket not up, then pending, then ready",
			steps: []step{
				unavailable,
				unavailable,
				healthStep(gpumanagerpb.HealthState_HEALTH_STATE_PENDING, ""),
				healthStep(gpumanagerpb.HealthState_HEALTH_STATE_READY, ""),
			},
			wantCalls: 4,
		},
		{
			name:       "ready with non-fatal errors",
			steps:      []step{healthStep(gpumanagerpb.HealthState_HEALTH_STATE_READY, "ECC errors on GPU 2")},
			wantCalls:  1,
			wantWarned: true,
		},
		{
			name: "bmsai failed",
			steps: []step{
				healthStep(gpumanagerpb.HealthState_HEALTH_STATE_PENDING, ""),
				healthStep(gpumanagerpb.HealthState_HEALTH_STATE_BMSAI_FAILED, "PRC knob 0x8 is 0"),
			},
			wantErr:   "PRC knob 0x8 is 0",
			wantCalls: 2,
		},
		{
			name:      "pending forever times out",
			steps:     []step{healthStep(gpumanagerpb.HealthState_HEALTH_STATE_PENDING, "")},
			wantErrIs: context.DeadlineExceeded,
		},
		{
			name:      "unavailable forever times out with last error",
			steps:     []step{unavailable},
			wantErr:   "connection refused",
			wantErrIs: context.DeadlineExceeded,
		},
		{
			name:      "unspecified is not final",
			steps:     []step{healthStep(gpumanagerpb.HealthState_HEALTH_STATE_UNSPECIFIED, "")},
			wantErrIs: context.DeadlineExceeded,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			healthz, calls := scripted(tc.steps...)
			logger := &testLogger{}
			err := waitForReady(t.Context(), healthz, 200*time.Millisecond, time.Millisecond, logger)
			if tc.wantErr == "" && tc.wantErrIs == nil {
				if err != nil {
					t.Errorf("waitForReady() = %v, want nil", err)
				}
			} else {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Errorf("waitForReady() = %v, want error containing %q", err, tc.wantErr)
				}
				if tc.wantErrIs != nil && !errors.Is(err, tc.wantErrIs) {
					t.Errorf("waitForReady() = %v, want error wrapping %v", err, tc.wantErrIs)
				}
			}
			if tc.wantCalls != 0 && *calls != tc.wantCalls {
				t.Errorf("waitForReady() called GetHealthz %d times, want %d", *calls, tc.wantCalls)
			}
			if got := len(logger.warns) > 0; got != tc.wantWarned {
				t.Errorf("waitForReady() logged a warning = %v, want %v", got, tc.wantWarned)
			}
		})
	}
}

type fakeServer struct {
	gpumanagerpb.UnimplementedGpuManagerServiceServer
}

func (fakeServer) GetHealthz(context.Context, *gpumanagerpb.GetHealthzRequest) (*gpumanagerpb.GetHealthzResponse, error) {
	return &gpumanagerpb.GetHealthzResponse{HealthState: gpumanagerpb.HealthState_HEALTH_STATE_READY}, nil
}

// TestWaitForReadyOverSocket starts gpu-manager's socket after the launcher
// starts waiting, as happens at boot.
func TestWaitForReadyOverSocket(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "gpu-manager.sock")
	gs := grpc.NewServer()
	gpumanagerpb.RegisterGpuManagerServiceServer(gs, fakeServer{})
	t.Cleanup(gs.Stop)

	done := make(chan struct{})
	t.Cleanup(func() { <-done }) // Runs before gs.Stop (cleanups are LIFO).
	go func() {
		defer close(done)
		time.Sleep(50 * time.Millisecond)
		lis, err := net.Listen("unix", sock)
		if err != nil {
			t.Errorf("net.Listen(%q) failed: %v", sock, err)
			return
		}
		go gs.Serve(lis)
	}()

	if err := WaitForReady(t.Context(), sock, 10*time.Second, 10*time.Millisecond, &testLogger{}); err != nil {
		t.Fatalf("WaitForReady() = %v, want nil", err)
	}
}

func TestWaitForReadyContextCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	healthz, _ := scripted(healthStep(gpumanagerpb.HealthState_HEALTH_STATE_PENDING, ""))
	if err := waitForReady(ctx, healthz, time.Minute, time.Millisecond, &testLogger{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("waitForReady() with cancelled context = %v, want error wrapping %v", err, context.Canceled)
	}
}
