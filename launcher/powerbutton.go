package launcher

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/google/go-tpm-tools/launcher/internal/logging"
)

const (
	udevDir                = "/run/udev/data"
	udevInputDevicePattern = "c13:*"
	powerSwitchTag         = "power-switch"

	eventMinorOffset = 64
	eventFilePrefix  = "/dev/input/event"

	procDevicesPath = "/proc/bus/input/devices"

	// The following constants are defined in Linux kernel's <linux/input-event-codes.h>
	evKey     = 1
	keyPower  = 116
	keyPower2 = 356 // 0x164
)

// findPowerButton attempts to find the /dev/input/eventX file for the power button.
// It prioritizes searching udev data files for the 'power-switch' tag, and falls back to /proc/bus/input/devices.
func (p *powerButtonListener) findPowerButton() (string, error) {
	return findPowerButtonIn(udevDir, procDevicesPath, p.logger)
}

func findPowerButtonIn(udevPath, procPath string, logger logging.Logger) (string, error) {
	// 1. Search files named c13:* (c = char device, 13 = input subsystem major number) in /run/udev/data/
	path, err := searchUdevFiles(udevPath, udevInputDevicePattern)
	if err == nil {
		logger.Info("Found the power button device file from /run/udev/data/c13:*")
		return path, nil
	}

	// 2. If not found, search all files in /run/udev/data/
	path, err = searchUdevFiles(udevPath, "*")
	if err == nil {
		logger.Info("Found the power button device file from /run/udev/data/*")
		return path, nil
	}

	// 3. If not found, look at /proc/bus/input/devices
	logger.Info("Trying to find the power button device file from /proc/bus/input/devices")
	return searchProcDevices(procPath)
}

// searchUdevFiles searches files in the udev directory matching the pattern for the power-switch tag.
func searchUdevFiles(dir, pattern string) (string, error) {
	files, err := filepath.Glob(filepath.Join(dir, pattern))
	if err != nil {
		return "", fmt.Errorf("globing udev files with %s failed: %w", pattern, err)
	}

	for _, file := range files {
		found, err := fileContainsTag(file, powerSwitchTag)
		if err != nil {
			continue
		}
		if found {
			// Extract the minor number from filename (e.g., "c13:65" -> "65")
			parts := strings.Split(filepath.Base(file), ":")
			if len(parts) == 2 {
				minor, err := strconv.Atoi(parts[1])
				if err == nil && minor >= eventMinorOffset {
					// Minor numbers for /dev/input/eventX start at 64 in Linux, so `minor - eventMinorOffset` gives us the event number.
					return fmt.Sprintf("%s%d", eventFilePrefix, minor-eventMinorOffset), nil
				}
			}
		}
	}
	return "", fmt.Errorf("not found in udev with pattern %s", pattern)
}

func fileContainsTag(filePath, tag string) (bool, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return false, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		// G: indicates tags in udev db v0, Q: indicates current tags in db v1.
		// Checking both ensures compatibility across different udev versions.
		if strings.HasPrefix(line, "G:") || strings.HasPrefix(line, "Q:") {
			if strings.Contains(line, tag) {
				return true, nil
			}
		}
	}
	return false, scanner.Err()
}

// searchProcDevices falls back to parsing /proc/bus/input/devices.
// We are looking for a block like the following in the file:
// I: Bus=0019 Vendor=0000 Product=0001 Version=0000
// N: Name="Power Button"
// P: Phys=LNXPWRBN/button/input0
// S: Sysfs=/devices/LNXSYSTM:00/LNXPWRBN:00/input/input2
// U: Uniq=
// H: Handlers=kbd event1
// B: PROP=0
// B: EV=3
// B: KEY=10000000000000 0
func parseProcDevices(r io.Reader) (string, error) {
	scanner := bufio.NewScanner(r)
	isPBBlock := false

	for scanner.Scan() {
		line := scanner.Text()

		if strings.Contains(line, `Name="Power Button"`) {
			isPBBlock = true
		}

		if isPBBlock && strings.Contains(line, "Handlers=") {
			fields := strings.Fields(line)
			for _, field := range fields {
				if strings.HasPrefix(field, "event") {
					return eventFilePrefix + strings.TrimPrefix(field, "event"), nil
				}
			}
		}

		if line == "" { // End of block
			isPBBlock = false
		}
	}

	if err := scanner.Err(); err != nil {
		return "", err
	}
	return "", errors.New("entry not found")
}

// searchProcDevices falls back to parsing /proc/bus/input/devices.
func searchProcDevices(devicesPath string) (string, error) {
	file, err := os.Open(devicesPath)
	if err != nil {
		return "", fmt.Errorf("opening %s failed: %w", devicesPath, err)
	}
	defer file.Close()

	eventPath, err := parseProcDevices(file)
	if err != nil {
		return "", fmt.Errorf("power button not found in %s: %w", devicesPath, err)
	}
	return eventPath, nil
}

type powerButtonListener struct {
	devPath string
	logger  logging.Logger
	file    io.ReadCloser
}

func newPowerButtonListener(logger logging.Logger) (*powerButtonListener, error) {
	p := &powerButtonListener{logger: logger}
	path, err := p.findPowerButton()
	if err != nil {
		return nil, fmt.Errorf("finding power button failed: %w", err)
	}
	p.devPath = path

	file, err := os.Open(p.devPath)
	if err != nil {
		return nil, fmt.Errorf("opening event file failed: %w", err)
	}
	p.file = file
	return p, nil
}

func (p *powerButtonListener) Close() error {
	if p.file != nil {
		return p.file.Close()
	}
	return nil
}

func (p *powerButtonListener) waitForShutdown() error {
	if p.file == nil {
		return fmt.Errorf("power button device is not open")
	}

	buf := make([]byte, 24)
	var nrRead int
	var evType, evCode uint16
	var evValue int32

	b := backoff.NewExponentialBackOff()
	b.MaxElapsedTime = 5 * time.Minute
	retries := backoff.WithMaxRetries(b, 5)

	for {
		retries.Reset()
		err := backoff.Retry(func() error {
			var readErr error
			nrRead, readErr = p.file.Read(buf)
			if errors.Is(readErr, os.ErrClosed) || errors.Is(readErr, io.EOF) || errors.Is(readErr, io.ErrClosedPipe) {
				return backoff.Permanent(readErr)
			}
			return readErr
		}, retries)
		if err != nil {
			return fmt.Errorf("reading event file failed after retries: %w", err)
		}

		switch nrRead {
		case 16:
			// 32-bit system layout
			evType = binary.LittleEndian.Uint16(buf[8:10])
			evCode = binary.LittleEndian.Uint16(buf[10:12])
			evValue = int32(binary.LittleEndian.Uint32(buf[12:16]))
		case 24:
			// 64-bit system layout
			evType = binary.LittleEndian.Uint16(buf[16:18])
			evCode = binary.LittleEndian.Uint16(buf[18:20])
			evValue = int32(binary.LittleEndian.Uint32(buf[20:24]))
		default:
			// Ignore partial or unknown event sizes
			continue
		}

		// Value > 0 handles both Press (1) and Repeat (2).
		if evType == evKey && (evCode == keyPower || evCode == keyPower2) && evValue > 0 {
			return nil
		}
	}
}
