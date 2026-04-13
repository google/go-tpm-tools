// Power button listener listens for power button events and triggers systemd poweroff.
package main

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
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
func findPowerButton() (string, error) {

	// 1. Search files named c13:* (c = char device, 13 = input subsystem major number) in /run/udev/data/
	path, err := searchUdevFiles(udevDir, udevInputDevicePattern)
	if err == nil {
		return path, nil
	}

	// 2. If not found, search all files in /run/udev/data/
	path, err = searchUdevFiles(udevDir, "*")
	if err == nil {
		return path, nil
	}

	// 3. If not found, look at /proc/bus/input/devices
	return searchProcDevices()
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
				if err == nil {
					// Minor numbers for /dev/input/eventX start at 64 in Linux, so `minor - eventMinorOffset` gives us the event number.
					return fmt.Sprintf("%s%d", eventFilePrefix, minor-eventMinorOffset), nil
				}
			}
		}
	}
	return "", fmt.Errorf("not found in udev with pattern %s", pattern)
}

// fileContainsTag checks if a udev data file contains the power-switch tag.
func fileContainsTag(filePath, tag string) (bool, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return false, err
	}
	defer func() {
		if err := file.Close(); err != nil {
			fmt.Println("Warning: failed to close file:", err)
		}
	}()

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
func searchProcDevices() (string, error) {
	file, err := os.Open(procDevicesPath)
	if err != nil {
		return "", fmt.Errorf("opening %s failed: %w", procDevicesPath, err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			fmt.Println("Warning: failed to close file:", err)
		}
	}()

	scanner := bufio.NewScanner(file)
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

	return "", fmt.Errorf("Power Button not found in %s", procDevicesPath)
}

func run() error {
	fmt.Println("Starting Power Button Listener...")

	path, err := findPowerButton()
	if err != nil {
		return fmt.Errorf("finding power button failed: %w", err)
	}

	fmt.Printf("Found Power Button at: %s\n", path)
	fmt.Println("Listening for shutdown signal...")

	// Open the event file
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("opening event file failed: %w", err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			fmt.Printf("Warning: failed to close file: %v\n", err)
		}
	}()

	if err := waitForPowerButtonEvent(file); err != nil {
		return fmt.Errorf("waiting for power button event failed: %w", err)
	}

	fmt.Println("Power button pressed! Triggering systemd poweroff...")

	// Trigger systemd poweroff
	if err := exec.Command("systemctl", "poweroff").Run(); err != nil {
		return fmt.Errorf("running systemctl poweroff failed: %w", err)
	}

	return nil
}

// waitForPowerButtonEvent blocks until a power button press event is detected.
func waitForPowerButtonEvent(file *os.File) error {
	buf := make([]byte, 24)
	for {
		n, err := file.Read(buf)
		if err != nil {
			return fmt.Errorf("reading event file failed: %w", err)
		}

		var evType, evCode uint16
		var evValue int32

		switch n {
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

func main() {
	if err := run(); err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
}
