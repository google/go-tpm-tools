// package main is a program that will start a container with attestation.
package main

import (
	"context"
	"errors"
	"io"
	"log"
	"os"

	"cloud.google.com/go/compute/metadata"
	"cloud.google.com/go/logging"
	"github.com/containerd/containerd"
	"github.com/containerd/containerd/defaults"
	"github.com/containerd/containerd/namespaces"
	"github.com/google/go-tpm-tools/client"
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

var rcMessage = map[int]string{
	successRC: "workload finished successfully, shutting down the VM",
	failRC:    "workload or launcher error, shutting down the VM",
	rebootRC:  "rebooting VM",
	holdRC:    "VM remains running",
}

var logger *log.Logger
var mdsClient *metadata.Client
var launchSpec spec.LaunchSpec

func main() {
	var exitCode int

	logger = log.Default()
	// log.Default() outputs to stderr; change to stdout.
	log.SetOutput(os.Stdout)
	logger.Println("TEE container launcher initiating")

	defer func() {
		// catch panic, will only output to stdout, because cloud logging closed
		// This should rarely happen (almost impossible), the only place can panic
		// recover here is in the deferred logClient.Close().
		if r := recover(); r != nil {
			logger.Println("Panic:", r)
			exitCode = 2
		}
		os.Exit(exitCode)
	}()

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

	defer func() {
		// catch panic, will also output to cloud logging if possible
		if r := recover(); r != nil {
			logger.Println("Panic:", r)
			exitCode = 2
		}
		msg, ok := rcMessage[exitCode]
		if ok {
			logger.Printf("TEE container launcher exiting with exit code: %d (%s)\n", exitCode, msg)
		} else {
			logger.Printf("TEE container launcher exiting with exit code: %d\n", exitCode)
		}
	}()
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
	containerdClient, err := containerd.New(defaults.DefaultAddress)
	if err != nil {
		return &launcher.RetryableError{Err: err}
	}
	defer containerdClient.Close()

	tpm, err := tpm2.OpenTPM("/dev/tpmrm0")
	if err != nil {
		return &launcher.RetryableError{Err: err}
	}
	defer tpm.Close()

	// check AK (EK signing) cert
	gceAk, err := client.GceAttestationKeyECC(tpm)
	if err != nil {
		return err
	}
	if gceAk.Cert() == nil {
		return errors.New("failed to find AKCert on this VM: try creating a new VM or contacting support")
	}
	gceAk.Close()

	token, err := launcher.RetrieveAuthToken(mdsClient)
	if err != nil {
		logger.Printf("failed to retrieve auth token: %v, using empty auth for image pulling\n", err)
	}

	ctx := namespaces.WithNamespace(context.Background(), namespaces.Default)
	r, err := launcher.NewRunner(ctx, containerdClient, token, launchSpec, mdsClient, tpm, logger)
	if err != nil {
		return err
	}
	defer r.Close(ctx)

	return r.Run(ctx)
}
