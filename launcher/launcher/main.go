// package main is a program that will start a container with attestation.
package main

import (
	"context"
	"io"
	"log"
	"os"

	"cloud.google.com/go/compute/metadata"
	"cloud.google.com/go/logging"
	"github.com/containerd/containerd"
	"github.com/containerd/containerd/defaults"
	"github.com/containerd/containerd/namespaces"
	"github.com/google/go-tpm-tools/launcher"
	"github.com/google/go-tpm-tools/launcher/spec"
	"github.com/google/go-tpm/tpm2"
)

const (
	logName = "confidential-space-launcher"
)

const (
	successRC = 0 // workload successful (no reboot)
	failRC    = 1 // workload or launcher internal failed (no reboot)
	// panic() returns 2
	rebootRC = 3 // reboot
	holdRC   = 4 // hold
)

var logger *log.Logger
var mdsClient *metadata.Client
var launchSpec spec.LaunchSpec

func main() {
	var exitCode int
	defer func() {
		os.Exit(exitCode)
	}()

	logger = log.Default()
	logger.Println("TEE container launcher initiating")

	mdsClient = metadata.NewClient(nil)
	projectID, err := mdsClient.ProjectID()
	if err != nil {
		logger.Printf("cannot get projectID, not in GCE? %v", err)
		// cannot get projectID from MDS, exit directly
		exitCode = failRC
		return
	}

	logClient, err := logging.NewClient(context.Background(), projectID)
	if err != nil {
		logger.Printf("cannot setup Cloud Logging, using the default stdout logger %v", err)
	} else {
		defer logClient.Close()
		logger.Printf("logs will be published to Cloud Logging under the log name %s\n", logName)
		logger = logClient.Logger(logName).StandardLogger(logging.Info)
		loggerAndStdout := io.MultiWriter(os.Stdout, logger.Writer()) // for now also print log to stdout
		logger.SetOutput(loggerAndStdout)
	}

	// get restart policy and ishardened from spec
	launchSpec, err = spec.GetLaunchSpec(mdsClient)
	if err != nil {
		logger.Println(err)
		// if cannot get launchSpec, exit directly
		exitCode = failRC
		return
	}

	if err = startLauncher(); err != nil {
		logger.Println(err)
	}

	exitCode = getExitCode(launchSpec.Hardened, launchSpec.RestartPolicy, err)
}

func getExitCode(isHardened bool, restartPolicy spec.RestartPolicy, err error) int {
	exitCode := 0

	// if in a debug image, will always hold
	if !isHardened {
		return holdRC
	}

	if err != nil {
		switch err.(type) {
		default:
			// non-retryable error
			exitCode = failRC
		case *launcher.RetryableError, *launcher.WorkloadError:
			if restartPolicy == spec.Always || restartPolicy == spec.OnFailure {
				exitCode = rebootRC
			} else {
				exitCode = failRC
			}
		}
	} else {
		// if no error
		if restartPolicy == spec.Always {
			exitCode = rebootRC
		} else {
			exitCode = successRC
		}
	}

	return exitCode
}

func startLauncher() error {
	logger.Println("Launch Spec: ", launchSpec)
	client, err := containerd.New(defaults.DefaultAddress)
	if err != nil {
		return &launcher.RetryableError{Err: err}
	}
	defer client.Close()

	tpm, err := tpm2.OpenTPM("/dev/tpmrm0")
	if err != nil {
		return &launcher.RetryableError{Err: err}
	}
	defer tpm.Close()

	token, err := launcher.RetrieveAuthToken(mdsClient)
	if err != nil {
		logger.Printf("failed to retrieve auth token: %v, using empty auth", err)
	}

	ctx := namespaces.WithNamespace(context.Background(), namespaces.Default)
	r, err := launcher.NewRunner(ctx, client, token, launchSpec, mdsClient, tpm, logger)
	if err != nil {
		return err
	}
	defer r.Close(ctx)

	return r.Run(ctx)
}
