// package main is a program that will start a container with attestation.
package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"cloud.google.com/go/compute/metadata"
	"github.com/containerd/containerd"
	"github.com/containerd/containerd/defaults"
	"github.com/containerd/containerd/namespaces"
	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm-tools/launcher"
	"github.com/google/go-tpm-tools/launcher/internal/logging"
	"github.com/google/go-tpm-tools/launcher/launcherfile"
	"github.com/google/go-tpm-tools/launcher/registryauth"
	"github.com/google/go-tpm-tools/launcher/spec"
	"github.com/google/go-tpm/legacy/tpm2"
)

const (
	successRC = 0 // workload successful (no reboot)
	failRC    = 1 // workload or launcher internal failed (no reboot)
	// panic() returns 2
	rebootRC = 3 // reboot
	holdRC   = 4 // hold
)

var expectedTPMDAParams = launcher.TPMDAParams{
	MaxTries:        0x20,    // 32 tries
	RecoveryTime:    0x1C20,  // 120 mins
	LockoutRecovery: 0x15180, // 24 hrs
}

var rcMessage = map[int]string{
	successRC: "workload finished successfully, shutting down the VM",
	failRC:    "workload or launcher error, shutting down the VM",
	rebootRC:  "rebooting VM",
	holdRC:    "VM remains running",
}

// BuildCommit shows the commit when building the binary, set by -ldflags when building
var BuildCommit = "dev"

var logger logging.Logger
var mdsClient *metadata.Client

var welcomeMessage = "TEE container launcher initiating"
var exitMessage = "TEE container launcher exiting"

var start time.Time

func main() {
	uptime, err := getUptime()
	if err != nil {
		logger.Error(fmt.Sprintf("error reading VM uptime: %v", err))
	}
	// Note the current time to later calculate launch time.
	start = time.Now()

	var exitCode int // by default exit code is 0
	ctx := context.Background()

	defer func() {
		os.Exit(exitCode)
	}()

	logger, err = logging.NewLogger(ctx)
	if err != nil {
		log.Default().Printf("failed to initialize logging")
		exitCode = failRC
		log.Default().Printf("%s, exit code: %d (%s)\n", exitMessage, exitCode, rcMessage[exitCode])
		return
	}
	defer logger.Close()

	logger.Info("Boot completed", "duration_sec", uptime)
	logger.Info(welcomeMessage, "build_commit", BuildCommit)

	if err := verifyFsAndMount(); err != nil {
		logger.Error(fmt.Sprintf("failed to verify filesystem and mounts: %v\n", err))
		exitCode = rebootRC
		logger.Error(exitMessage, "exit_code", exitCode, "exit_msg", rcMessage[exitCode])
		return
	}

	if err := os.MkdirAll(launcherfile.HostTmpPath, 0744); err != nil {
		logger.Error(fmt.Sprintf("failed to create %s: %v", launcherfile.HostTmpPath, err))
	}

	// Get RestartPolicy and IsHardened from spec
	mdsClient = metadata.NewClient(nil)
	launchSpec, err := spec.GetLaunchSpec(ctx, logger, mdsClient)
	if err != nil {
		logger.Error(fmt.Sprintf("failed to get launchspec, make sure you're running inside a GCE VM: %v", err))
		// if cannot get launchSpec, exit directly
		exitCode = failRC
		logger.Error(exitMessage, "exit_code", exitCode, "exit_msg", rcMessage[exitCode])
		return
	}

	defer func() {
		// Catch panic to attempt to output to Cloud Logging.
		if r := recover(); r != nil {
			logger.Error(fmt.Sprintf("Panic: %v", r))
			exitCode = 2
		}
		msg, ok := rcMessage[exitCode]
		if ok {
			logger.Info(exitMessage, "exit_code", exitCode, "exit_msg", msg)
		} else {
			logger.Info(exitMessage, "exit_code", exitCode)
		}
	}()
	if err = startLauncher(launchSpec, logger.SerialConsoleFile()); err != nil {
		logger.Error(err.Error())
	}

	workloadDuration := time.Since(start)
	logger.Info("Workload completed",
		"workload", launchSpec.ImageRef,
		"workload_execution_sec", workloadDuration.Seconds(),
	)

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

func getUptime() (string, error) {
	file, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return "", fmt.Errorf("error opening /proc/uptime: %v", err)
	}

	// proc/uptime contains two values separated by a space. We only need the first.
	split := bytes.Split(file, []byte(" "))
	if len(split) != 2 {
		return "", fmt.Errorf("unexpected /proc/uptime contents: %s", file)
	}

	return string(split[0]), nil
}

func startLauncher(launchSpec spec.LaunchSpec, serialConsole *os.File) error {
	logger.Info(fmt.Sprintf("Launch Spec: %+v", launchSpec))
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

	// check DA info, don't crash if failed
	daInfo, err := launcher.GetTPMDAInfo(tpm)
	if err != nil {
		logger.Error(fmt.Sprintf("Failed to get DA Info: %v", err))
	} else {
		if !daInfo.StartupClearOrderly {
			logger.Warn(fmt.Sprintf("Failed orderly startup. Avoid using instance reset. Instead, use instance stop/start. DA lockout counter incremented: LockoutCounter: %d / MaxAuthFail: %d", daInfo.LockoutCounter, daInfo.MaxTries))
		}

		if err := launcher.SetTPMDAParams(tpm, expectedTPMDAParams); err != nil {
			logger.Error(fmt.Sprintf("Failed to set DA params: %v", err))
		}

		daInfo, err := launcher.GetTPMDAInfo(tpm)
		if err != nil {
			logger.Error(fmt.Sprintf("Failed to get DA Info: %v", err))
		} else {
			logger.Info(fmt.Sprintf("Updated TPM DA params: %+v", daInfo))
		}
	}

	// check AK (EK signing) cert
	gceAk, err := client.GceAttestationKeyECC(tpm)
	if err != nil {
		return err
	}
	if gceAk.Cert() == nil {
		return errors.New("failed to find AKCert on this VM: try creating a new VM or contacting support")
	}
	gceAk.Close()

	token, err := registryauth.RetrieveAuthToken(context.Background(), mdsClient)
	if err != nil {
		logger.Info(fmt.Sprintf("failed to retrieve auth token: %v, using empty auth for image pulling\n", err))
	}

	logger.Info("Launch started", "duration_sec", time.Since(start).Seconds())

	ctx := namespaces.WithNamespace(context.Background(), namespaces.Default)
	r, err := launcher.NewRunner(ctx, containerdClient, token, launchSpec, mdsClient, tpm, logger, serialConsole)
	if err != nil {
		return err
	}
	defer r.Close(ctx)

	return r.Run(ctx)
}

// verifyFsAndMount checks the partitions/mounts are as expected, based on the command output reported by OS.
// These checks are not a security guarantee.
func verifyFsAndMount() error {
	dmLsOutput, err := exec.Command("dmsetup", "ls").Output()
	if err != nil {
		return fmt.Errorf("failed to call `dmsetup ls`: %v %s", err, string(dmLsOutput))
	}

	dmDevs := strings.Split(string(dmLsOutput), "\n")
	devNameToDevNo := make(map[string]string)
	for _, dmDev := range dmDevs {
		if dmDev == "" {
			continue
		}
		devFields := strings.Fields(dmDev)
		if len(devFields) != 2 {
			continue
		}
		devMajorMinor := strings.ReplaceAll(strings.ReplaceAll(devFields[1], "(", ""), ")", "")
		devNameToDevNo[devFields[0]] = devMajorMinor
	}
	var cryptNo, zeroNo string
	var ok bool
	if _, ok = devNameToDevNo["protected_stateful_partition"]; !ok {
		return fmt.Errorf("failed to find /dev/mapper/protected_stateful_partition: %s", string(dmLsOutput))
	}
	if cryptNo, ok = devNameToDevNo["protected_stateful_partition_crypt"]; !ok {
		return fmt.Errorf("failed to find /dev/mapper/protected_stateful_partition_crypt: %s", string(dmLsOutput))
	}
	if zeroNo, ok = devNameToDevNo["protected_stateful_partition_zero"]; !ok {
		return fmt.Errorf("failed to find /dev/mapper/protected_stateful_partition_zero: %s", string(dmLsOutput))
	}

	dmTableCloneOutput, err := exec.Command("dmsetup", "table", "/dev/mapper/protected_stateful_partition").Output()
	if err != nil {
		return fmt.Errorf("failed to check /dev/mapper/protected_stateful_partition status: %v %s", err, string(dmTableCloneOutput))
	}
	cloneTable := strings.Fields(string(dmTableCloneOutput))
	// https://docs.kernel.org/admin-guide/device-mapper/dm-clone.html
	if len(cloneTable) < 7 {
		return fmt.Errorf("clone table does not match expected format: %s", string(dmTableCloneOutput))
	}
	if cloneTable[2] != "clone" {
		return fmt.Errorf("protected_stateful_partition is not a dm-clone device: %s", string(dmTableCloneOutput))
	}
	if cloneTable[4] != cryptNo {
		return fmt.Errorf("protected_stateful_partition does not have protected_stateful_partition_crypt as a destination device: %s", string(dmTableCloneOutput))
	}
	if cloneTable[5] != zeroNo {
		return fmt.Errorf("protected_stateful_partition protected_stateful_partition_zero as a source device: %s", string(dmTableCloneOutput))
	}

	// Check protected_stateful_partition_crypt is encrypted and is on integrity protection.
	dmTableCryptOutput, err := exec.Command("dmsetup", "table", "/dev/mapper/protected_stateful_partition_crypt").Output()
	if err != nil {
		return fmt.Errorf("failed to check /dev/mapper/protected_stateful_partition_crypt status: %v %s", err, string(dmTableCryptOutput))
	}
	matched := regexp.MustCompile(`integrity:28:aead`).FindString(string(dmTableCryptOutput))
	if len(matched) == 0 {
		return fmt.Errorf("stateful partition is not integrity protected: \n%s", dmTableCryptOutput)
	}
	matched = regexp.MustCompile(`capi:gcm\(aes\)-random`).FindString(string(dmTableCryptOutput))
	if len(matched) == 0 {
		return fmt.Errorf("stateful partition is not using the aes-gcm-random cipher: \n%s", dmTableCryptOutput)
	}

	// Make sure /var/lib/containerd is on protected_stateful_partition.
	findmountOutput, err := exec.Command("findmnt", "/dev/mapper/protected_stateful_partition").Output()
	if err != nil {
		return fmt.Errorf("failed to findmnt /dev/mapper/protected_stateful_partition: %v %s", err, string(findmountOutput))
	}
	matched = regexp.MustCompile(`/var/lib/containerd\s+/dev/mapper/protected_stateful_partition\[/var/lib/containerd\]\s+ext4\s+rw,nosuid,nodev,relatime,commit=30`).FindString(string(findmountOutput))
	if len(matched) == 0 {
		return fmt.Errorf("/var/lib/containerd was not mounted on the protected_stateful_partition: \n%s", findmountOutput)
	}
	matched = regexp.MustCompile(`/var/lib/google\s+/dev/mapper/protected_stateful_partition\[/var/lib/google\]\s+ext4\s+rw,nosuid,nodev,relatime,commit=30`).FindString(string(findmountOutput))
	if len(matched) == 0 {
		return fmt.Errorf("/var/lib/google was not mounted on the protected_stateful_partition: \n%s", findmountOutput)
	}

	// Check /tmp is on tmpfs.
	findmntOutput, err := exec.Command("findmnt", "tmpfs").Output()
	if err != nil {
		return fmt.Errorf("failed to findmnt tmpfs: %v %s", err, string(findmntOutput))
	}
	matched = regexp.MustCompile(`/tmp\s+tmpfs\s+tmpfs`).FindString(string(findmntOutput))
	if len(matched) == 0 {
		return fmt.Errorf("/tmp was not mounted on the tmpfs: \n%s", findmntOutput)
	}

	// Check verity status on vroot and oemroot.
	cryptSetupOutput, err := exec.Command("cryptsetup", "status", "vroot").Output()
	if err != nil {
		return fmt.Errorf("failed to check vroot status: %v %s", err, string(cryptSetupOutput))
	}
	if !strings.Contains(string(cryptSetupOutput), "/dev/mapper/vroot is active and is in use.") {
		return fmt.Errorf("/dev/mapper/vroot was not mounted correctly: \n%s", cryptSetupOutput)
	}
	cryptSetupOutput, err = exec.Command("cryptsetup", "status", "oemroot").Output()
	if err != nil {
		return fmt.Errorf("failed to check oemroot status: %v %s", err, string(cryptSetupOutput))
	}
	if !strings.Contains(string(cryptSetupOutput), "/dev/mapper/oemroot is active and is in use.") {
		return fmt.Errorf("/dev/mapper/oemroot was not mounted correctly: \n%s", cryptSetupOutput)
	}

	return nil
}
