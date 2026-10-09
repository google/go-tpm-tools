// Package gpumanager waits for the GB300 gpu-manager sidecar to finish
// preparing the GPUs before the launcher touches them.
package gpumanager

import (
	"context"
	"fmt"
	"time"

	gpumanagerpb "github.com/GoogleCloudPlatform/confidential-space/server/proto/gen/gpumanager"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const (
	// DefaultSocketPath is where gpu-manager serves GpuManagerService.
	DefaultSocketPath = "/run/gpu-manager/gpu-manager.sock"
	// DefaultTimeout bounds how long the launcher waits for a final state.
	// GPU setup unloads the driver, switches BMSAI mode, resets the GPUs and
	// reloads the driver, which takes a few minutes.
	DefaultTimeout = 20 * time.Minute
	// DefaultPollInterval is how often GetHealthz is called.
	DefaultPollInterval = 5 * time.Second

	rpcTimeout = 10 * time.Second
)

// Logger is the subset of the launcher logger used here.
type Logger interface {
	Info(msg string, args ...any)
	Warn(msg string, args ...any)
}

// healthzFunc returns the current gpu-manager health.
type healthzFunc func(ctx context.Context) (*gpumanagerpb.GetHealthzResponse, error)

// WaitForReady polls gpu-manager over socketPath until it reports a final
// state. It returns nil for HEALTH_STATE_READY and an error for
// HEALTH_STATE_BMSAI_FAILED, or if no final state arrives before timeout. It
// fails closed: the GPUs must not be used unless this returns nil.
//
// The socket may not exist yet when this is called, since gpu-manager starts
// in parallel with the launcher; connection errors are retried until timeout.
func WaitForReady(ctx context.Context, socketPath string, timeout, pollInterval time.Duration, logger Logger) error {
	conn, err := grpc.NewClient("unix://"+socketPath, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return fmt.Errorf("failed to create gpu-manager client for %s: %w", socketPath, err)
	}
	defer conn.Close()
	client := gpumanagerpb.NewGpuManagerServiceClient(conn)
	healthz := func(ctx context.Context) (*gpumanagerpb.GetHealthzResponse, error) {
		return client.GetHealthz(ctx, &gpumanagerpb.GetHealthzRequest{})
	}
	return waitForReady(ctx, healthz, timeout, pollInterval, logger)
}

func waitForReady(ctx context.Context, healthz healthzFunc, timeout, pollInterval time.Duration, logger Logger) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	start := time.Now()
	var lastErr error
	lastState := gpumanagerpb.HealthState_HEALTH_STATE_UNSPECIFIED
	for {
		rpcCtx, rpcCancel := context.WithTimeout(ctx, rpcTimeout)
		resp, err := healthz(rpcCtx)
		rpcCancel()
		lastErr = err
		if err == nil {
			state := resp.GetHealthState()
			if state != lastState {
				logger.Info("gpu-manager health state changed", "state", state.String(), "elapsed", time.Since(start).Round(time.Second).String())
				lastState = state
			}
			switch state {
			case gpumanagerpb.HealthState_HEALTH_STATE_READY:
				if msg := resp.GetErrorMessage(); msg != "" {
					// Non-fatal: BMSAI is enabled, but a diagnostic failed.
					logger.Warn("gpu-manager is ready with non-fatal errors", "error_message", msg)
				}
				return nil
			case gpumanagerpb.HealthState_HEALTH_STATE_BMSAI_FAILED:
				return fmt.Errorf("gpu-manager failed to enable BMSAI on the GPUs: %q", resp.GetErrorMessage())
			}
			// PENDING (or UNSPECIFIED from a misbehaving server): keep polling.
		}

		select {
		case <-ctx.Done():
			return fmt.Errorf("gpu-manager reported no final health state after %v (last state %v, last GetHealthz error: %v): %w", time.Since(start).Round(time.Second), lastState, lastErr, ctx.Err())
		case <-time.After(pollInterval):
		}
	}
}
