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
	"github.com/google/go-tpm-tools/launcher"
	"github.com/google/go-tpm-tools/launcher/internal/logging"
	"github.com/google/go-tpm-tools/launcher/launcherfile"
	"github.com/google/go-tpm-tools/launcher/spec"
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

// BuildCommit shows the commit when building the binary, set by -ldflags when building
var BuildCommit = "dev"

const serialConsoleFile = "/dev/console"

const welcomeMessage = "TEE container launcher initiating"
const exitMessage = "TEE container launcher exiting"

func main() {
	uptime, err := getUptime()
	if err != nil {
		// logger is not initialized yet.
		log.Default().Printf("error reading VM uptime: %v", err)
	}
	// Note the current time to later calculate launch time.
	start := time.Now()

	var exitCode int // by default exit code is 0
	ctx := context.Background()

	defer func() {
		os.Exit(exitCode)
	}()

	serialConsole, err := os.OpenFile(serialConsoleFile, os.O_WRONLY, 0)
	if err != nil {
		log.Default().Printf("Failed to open serial console: %v", err)
		exitCode = failRC
		log.Default().Printf("%s, exit code: %d (%s)\n", exitMessage, exitCode, rcMessage[exitCode])
		return
	}
	defer serialConsole.Close()

	serialLogger := logging.NewSerialLogger(serialConsole)

	pool, err := launcher.GoogleCertPool()
	if err != nil {
		serialLogger.Error(fmt.Sprintf("failed to load Google root certificates: %v", err))
		exitCode = failRC
		serialLogger.Error(exitMessage, "exit_code", exitCode, "exit_msg", rcMessage[exitCode])
		return
	}

	workloadLogger, err := logging.NewCloudLogger(ctx, pool)
	if err != nil {
		serialLogger.Error(fmt.Sprintf("failed to initialize cloud logging: %v", err))
		exitCode = failRC
		serialLogger.Error(exitMessage, "exit_code", exitCode, "exit_msg", rcMessage[exitCode])
		return
	}
	defer workloadLogger.Close()

	logger := logging.DualLogger(workloadLogger, serialLogger)

	pinnedClient, err := launcher.PinnedHTTPClient(pool)
	if err != nil {
		logger.Error(fmt.Sprintf("failed to initialize Google root HTTP client: %v", err))
		exitCode = failRC
		logger.Error(exitMessage, "exit_code", exitCode, "exit_msg", rcMessage[exitCode])
		return
	}

	googleClient, err := launcher.AuthenticatedGoogleHTTPClient(ctx, pinnedClient)
	if err != nil {
		logger.Error(fmt.Sprintf("failed to initialize authenticated Google HTTP client: %v", err))
		exitCode = failRC
		logger.Error(exitMessage, "exit_code", exitCode, "exit_msg", rcMessage[exitCode])
		return
	}

	logger.Info("Boot completed", "duration_sec", uptime)
	logger.Info(welcomeMessage, "build_commit", BuildCommit)

	if err := os.MkdirAll(launcherfile.HostTmpPath, 0755); err != nil {
		logger.Error(fmt.Sprintf("failed to create %s: %v", launcherfile.HostTmpPath, err))
	}

	// Get RestartPolicy and IsHardened from spec
	mdsClient := metadata.NewClient(nil)
	launchSpec, err := spec.GetLaunchSpec(ctx, logger, mdsClient)
	if err != nil {
		logger.Error(fmt.Sprintf("failed to get launchspec, make sure you're running inside a GCE VM: %v", err))
		// if cannot get launchSpec, exit directly
		exitCode = failRC
		logger.Error(exitMessage, "exit_code", exitCode, "exit_msg", rcMessage[exitCode])
		return
	}
	// Do not delete the folliwing line, this line is used for tests.
	logger.Info(fmt.Sprintf("Launch Spec: %+v", launchSpec.LogFriendly()))

	verifier := osMountVerifier{}
	if err := verifyDiskIntegrity(verifier); err != nil {
		logger.Error(fmt.Sprintf("failed to verify disk integrity: %v\n", err))
		exitCode = rebootRC
		logger.Error(exitMessage, "exit_code", exitCode, "exit_msg", rcMessage[exitCode])
		return
	}
	if err := verifyMounts(launchSpec, verifier); err != nil {
		logger.Error(fmt.Sprintf("failed to verify mounts: %v\n", err))
		exitCode = rebootRC
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
	if err = launcher.StartLauncher(ctx, launchSpec, logger, workloadLogger, serialConsole, pinnedClient, googleClient); err != nil {
		logger.Error(err.Error())
		var tpmOpenErr *launcher.TPMOpenError
		if errors.As(err, &tpmOpenErr) {
			exitCode = rebootRC
			return
		}
		var tpmInitErr *launcher.TPMInitError
		if errors.As(err, &tpmInitErr) {
			exitCode = getExitCode(launchSpec.Hardened, launchSpec.RestartPolicy, err)
			return
		}
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

// verifyFsAndMount checks the partitions/mounts are as expected, based on the command output reported by OS.
// These checks are not a security guarantee.
func verifyDiskIntegrity(verifier integrityVerifier) error {
	dmLsOutput, err := verifier.DmsetupLs()
	if err != nil {
		return fmt.Errorf("failed to call `dmsetup ls`: %v %s", err, dmLsOutput)
	}

	dmDevs := strings.Split(dmLsOutput, "\n")
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
		return fmt.Errorf("failed to find /dev/mapper/protected_stateful_partition: %s", dmLsOutput)
	}
	if cryptNo, ok = devNameToDevNo["protected_stateful_partition_crypt"]; !ok {
		return fmt.Errorf("failed to find /dev/mapper/protected_stateful_partition_crypt: %s", dmLsOutput)
	}
	if zeroNo, ok = devNameToDevNo["protected_stateful_partition_zero"]; !ok {
		return fmt.Errorf("failed to find /dev/mapper/protected_stateful_partition_zero: %s", dmLsOutput)
	}

	dmTableCloneOutput, err := verifier.DmsetupTable("/dev/mapper/protected_stateful_partition")
	if err != nil {
		return fmt.Errorf("failed to check /dev/mapper/protected_stateful_partition status: %v %s", err, dmTableCloneOutput)
	}
	cloneTable := strings.Fields(dmTableCloneOutput)
	// https://docs.kernel.org/admin-guide/device-mapper/dm-clone.html
	if len(cloneTable) < 7 {
		return fmt.Errorf("clone table does not match expected format: %s", dmTableCloneOutput)
	}
	if cloneTable[2] != "clone" {
		return fmt.Errorf("protected_stateful_partition is not a dm-clone device: %s", dmTableCloneOutput)
	}
	if cloneTable[4] != cryptNo {
		return fmt.Errorf("protected_stateful_partition does not have protected_stateful_partition_crypt as a destination device: %s", dmTableCloneOutput)
	}
	if cloneTable[5] != zeroNo {
		return fmt.Errorf("protected_stateful_partition protected_stateful_partition_zero as a source device: %s", dmTableCloneOutput)
	}

	// Check protected_stateful_partition_crypt is encrypted and is on integrity protection.
	dmTableCryptOutput, err := verifier.DmsetupTable("/dev/mapper/protected_stateful_partition_crypt")
	if err != nil {
		return fmt.Errorf("failed to check /dev/mapper/protected_stateful_partition_crypt status: %v %s", err, dmTableCryptOutput)
	}
	matched := regexp.MustCompile(`integrity:28:aead`).FindString(dmTableCryptOutput)
	if len(matched) == 0 {
		return fmt.Errorf("stateful partition is not integrity protected: \n%s", dmTableCryptOutput)
	}
	matched = regexp.MustCompile(`capi:gcm\(aes\)-random`).FindString(dmTableCryptOutput)
	if len(matched) == 0 {
		return fmt.Errorf("stateful partition is not using the aes-gcm-random cipher: \n%s", dmTableCryptOutput)
	}

	// Check verity status on vroot and oemroot.
	cryptSetupOutput, err := verifier.CryptsetupStatus("vroot")
	if err != nil {
		return fmt.Errorf("failed to check vroot status: %v %s", err, cryptSetupOutput)
	}
	if !strings.Contains(cryptSetupOutput, "/dev/mapper/vroot is active and is in use.") {
		return fmt.Errorf("/dev/mapper/vroot was not mounted correctly: \n%s", cryptSetupOutput)
	}
	cryptSetupOutput, err = verifier.CryptsetupStatus("oemroot")
	if err != nil {
		return fmt.Errorf("failed to check oemroot status: %v %s", err, cryptSetupOutput)
	}
	if !strings.Contains(cryptSetupOutput, "/dev/mapper/oemroot is active and is in use.") {
		return fmt.Errorf("/dev/mapper/oemroot was not mounted correctly: \n%s", cryptSetupOutput)
	}

	return nil
}

func verifyMounts(launchSpec spec.LaunchSpec, verifier mountVerifier) error {
	// Make sure /var/lib/containerd is on protected_stateful_partition.
	findmountOutput, err := verifier.Findmnt("/dev/mapper/protected_stateful_partition")
	if err != nil {
		return fmt.Errorf("failed to findmnt /dev/mapper/protected_stateful_partition: %v %s", err, findmountOutput)
	}
	matched := regexp.MustCompile(`/var/lib/containerd\s+/dev/mapper/protected_stateful_partition\[/var/lib/containerd\]\s+ext4\s+rw,nosuid,nodev,relatime,commit=30`).FindString(findmountOutput)
	if len(matched) == 0 {
		return fmt.Errorf("/var/lib/containerd was not mounted on the protected_stateful_partition: \n%s", findmountOutput)
	}
	if !launchSpec.Experiments.BcMode {
		matched = regexp.MustCompile(`/var/lib/google\s+/dev/mapper/protected_stateful_partition\[/var/lib/google\]\s+ext4\s+rw,nosuid,nodev,relatime,commit=30`).FindString(findmountOutput)
		if len(matched) == 0 {
			return fmt.Errorf("/var/lib/google was not mounted on the protected_stateful_partition: \n%s", findmountOutput)
		}
	}

	// Check /tmp is on tmpfs.
	findmntOutput, err := verifier.Findmnt("tmpfs")
	if err != nil {
		return fmt.Errorf("failed to findmnt tmpfs: %v %s", err, findmntOutput)
	}
	matched = regexp.MustCompile(`/tmp\s+tmpfs\s+tmpfs`).FindString(findmntOutput)
	if len(matched) == 0 {
		return fmt.Errorf("/tmp was not mounted on the tmpfs: \n%s", findmntOutput)
	}

	return nil
}

type integrityVerifier interface {
	DmsetupLs() (string, error)
	DmsetupTable(name string) (string, error)
	CryptsetupStatus(name string) (string, error)
}

type mountVerifier interface {
	Findmnt(target string) (string, error)
}

type osMountVerifier struct{}

func (osMountVerifier) DmsetupLs() (string, error) {
	out, err := exec.Command("dmsetup", "ls").Output()
	return string(out), err
}

func (osMountVerifier) DmsetupTable(name string) (string, error) {
	out, err := exec.Command("dmsetup", "table", name).Output()
	return string(out), err
}

func (osMountVerifier) Findmnt(target string) (string, error) {
	out, err := exec.Command("findmnt", target).Output()
	return string(out), err
}

func (osMountVerifier) CryptsetupStatus(name string) (string, error) {
	out, err := exec.Command("cryptsetup", "status", name).Output()
	return string(out), err
}
