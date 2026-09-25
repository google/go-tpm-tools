package launcher

import (
	"encoding/binary"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/go-tpm-tools/launcher/internal/logging"
)

func encodeEvent64(evType, evCode uint16, evValue int32) []byte {
	buf := make([]byte, 24)
	binary.LittleEndian.PutUint16(buf[16:18], evType)
	binary.LittleEndian.PutUint16(buf[18:20], evCode)
	binary.LittleEndian.PutUint32(buf[20:24], uint32(evValue))
	return buf
}

func encodeEvent32(evType, evCode uint16, evValue int32) []byte {
	buf := make([]byte, 16)
	binary.LittleEndian.PutUint16(buf[8:10], evType)
	binary.LittleEndian.PutUint16(buf[10:12], evCode)
	binary.LittleEndian.PutUint32(buf[12:16], uint32(evValue))
	return buf
}

func TestWaitForShutdown_64BitKeyPowerCodes(t *testing.T) {
	testCases := []struct {
		name    string
		keyCode uint16
		value   int32
	}{
		{
			name:    "KEY_POWER press",
			keyCode: keyPower,
			value:   1,
		},
		{
			name:    "KEY_POWER2 press",
			keyCode: keyPower2,
			value:   1,
		},
		{
			name:    "KEY_POWER repeat",
			keyCode: keyPower,
			value:   2,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			pr, pw := io.Pipe()
			defer pr.Close()
			defer pw.Close()

			listener := &powerButtonListener{
				file:   pr,
				logger: logging.SimpleLogger(),
			}

			errCh := make(chan error, 1)
			go func() {
				errCh <- listener.waitForShutdown()
			}()

			if _, err := pw.Write(encodeEvent64(evKey, tc.keyCode, tc.value)); err != nil {
				t.Fatalf("failed to write event: %v", err)
			}

			select {
			case err := <-errCh:
				if err != nil {
					t.Errorf("waitForShutdown() returned unexpected error: %v", err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("timed out waiting for waitForShutdown() to return")
			}
		})
	}
}

func TestWaitForShutdown_32BitKeyPowerPress(t *testing.T) {
	pr, pw := io.Pipe()
	defer pr.Close()
	defer pw.Close()

	listener := &powerButtonListener{
		file:   pr,
		logger: logging.SimpleLogger(),
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- listener.waitForShutdown()
	}()

	if _, err := pw.Write(encodeEvent32(evKey, keyPower, 1)); err != nil {
		t.Fatalf("failed to write event: %v", err)
	}

	select {
	case err := <-errCh:
		if err != nil {
			t.Errorf("waitForShutdown() returned unexpected error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for waitForShutdown() to return")
	}
}

func TestWaitForShutdown_IgnoresKeyRelease(t *testing.T) {
	pr, pw := io.Pipe()
	defer pr.Close()
	defer pw.Close()

	listener := &powerButtonListener{
		file:   pr,
		logger: logging.SimpleLogger(),
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- listener.waitForShutdown()
	}()

	// Value 0 indicates key release. Must be ignored until a key press is written.
	if _, err := pw.Write(encodeEvent64(evKey, keyPower, 0)); err != nil {
		t.Fatalf("failed to write release event: %v", err)
	}

	// Follow with an actual key press to verify only the press unblocks.
	if _, err := pw.Write(encodeEvent64(evKey, keyPower, 1)); err != nil {
		t.Fatalf("failed to write press event: %v", err)
	}

	select {
	case err := <-errCh:
		if err != nil {
			t.Errorf("waitForShutdown() returned unexpected error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for waitForShutdown() to unblock on key press")
	}
}

func TestWaitForShutdown_IgnoresIrrelevantEvents(t *testing.T) {
	pr, pw := io.Pipe()
	defer pr.Close()
	defer pw.Close()

	listener := &powerButtonListener{
		file:   pr,
		logger: logging.SimpleLogger(),
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- listener.waitForShutdown()
	}()

	// Non-power key (Enter = 28)
	if _, err := pw.Write(encodeEvent64(evKey, 28, 1)); err != nil {
		t.Fatalf("failed to write irrelevant key event: %v", err)
	}
	// Non-key event type (EV_SYN = 0)
	if _, err := pw.Write(encodeEvent64(0, 0, 0)); err != nil {
		t.Fatalf("failed to write EV_SYN event: %v", err)
	}
	// Malformed partial chunk
	if _, err := pw.Write([]byte{0x01, 0x02, 0x03, 0x04}); err != nil {
		t.Fatalf("failed to write partial chunk: %v", err)
	}

	// Now send valid key power to prove loop was still active
	if _, err := pw.Write(encodeEvent64(evKey, keyPower, 1)); err != nil {
		t.Fatalf("failed to write power event: %v", err)
	}

	select {
	case err := <-errCh:
		if err != nil {
			t.Errorf("waitForShutdown() returned unexpected error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for waitForShutdown() to unblock")
	}
}

func TestWaitForShutdown_NilFileReturnsError(t *testing.T) {
	listener := &powerButtonListener{
		file:   nil,
		logger: logging.SimpleLogger(),
	}

	err := listener.waitForShutdown()
	if err == nil {
		t.Fatal("waitForShutdown() succeeded, expected error on nil file")
	}
	if !strings.Contains(err.Error(), "power button device is not open") {
		t.Errorf("waitForShutdown() error = %q, want error containing 'power button device is not open'", err)
	}
}

func TestWaitForShutdown_ReaderClosedReturnsError(t *testing.T) {
	pr, pw := io.Pipe()
	pw.Close()
	pr.Close()

	listener := &powerButtonListener{
		file:   pr,
		logger: logging.SimpleLogger(),
	}

	err := listener.waitForShutdown()
	if err == nil {
		t.Fatal("waitForShutdown() succeeded, expected error when reader is closed")
	}
}

func TestPowerButtonListener_CloseUnblocksWaitForShutdown(t *testing.T) {
	pr, pw := io.Pipe()
	defer pw.Close()

	listener := &powerButtonListener{
		file:   pr,
		logger: logging.SimpleLogger(),
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- listener.waitForShutdown()
	}()

	// Closing the listener must unblock the in-flight read
	if err := listener.Close(); err != nil {
		t.Fatalf("listener.Close() error: %v", err)
	}

	select {
	case err := <-errCh:
		if err == nil {
			t.Error("expected waitForShutdown to return an error when closed, got nil")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for waitForShutdown to unblock after Close()")
	}
}

func TestParseProcDevices_Found(t *testing.T) {
	content := `I: Bus=0019 Vendor=0000 Product=0001 Version=0000
N: Name="Power Button"
P: Phys=LNXPWRBN/button/input0
S: Sysfs=/devices/LNXSYSTM:00/LNXPWRBN:00/input/input2
U: Uniq=
H: Handlers=kbd event3
B: PROP=0
B: EV=3
B: KEY=10000000000000 0

I: Bus=0011 Vendor=0001 Product=0001 Version=ab41
N: Name="AT Translated Set 2 keyboard"
P: Phys=isa0060/serio0/input0
S: Sysfs=/devices/platform/i8042/serio0/input/input0
U: Uniq=
H: Handlers=sysrq kbd event0
B: PROP=0
`
	got, err := parseProcDevices(strings.NewReader(content))
	if err != nil {
		t.Fatalf("parseProcDevices() error = %v", err)
	}

	want := "/dev/input/event3"
	if got != want {
		t.Errorf("parseProcDevices() = %q, want %q", got, want)
	}
}

func TestParseProcDevices_NotFound(t *testing.T) {
	content := `I: Bus=0011 Vendor=0001 Product=0001 Version=ab41
N: Name="AT Translated Set 2 keyboard"
H: Handlers=kbd event0
`
	_, err := parseProcDevices(strings.NewReader(content))
	if err == nil {
		t.Fatal("parseProcDevices() succeeded, expected error when Power Button is absent")
	}
}

func TestParseProcDevices_PowerButtonWithoutEventHandler(t *testing.T) {
	content := `I: Bus=0019 Vendor=0000 Product=0001 Version=0000
N: Name="Power Button"
H: Handlers=kbd
`
	_, err := parseProcDevices(strings.NewReader(content))
	if err == nil {
		t.Fatal("parseProcDevices() succeeded, expected error when Power Button lacks event handler")
	}
}

func TestSearchUdevFiles_FoundV1Tag(t *testing.T) {
	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, "c13:65")
	content := "S:input/by-path/platform-i8042-serio-0-event-kbd\nQ:power-switch\n"
	if err := os.WriteFile(filePath, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write test udev file: %v", err)
	}

	got, err := searchUdevFiles(tempDir, "c13:*")
	if err != nil {
		t.Fatalf("searchUdevFiles() error = %v", err)
	}

	// Minor 65: 65 - 64 = 1 -> /dev/input/event1
	want := "/dev/input/event1"
	if got != want {
		t.Errorf("searchUdevFiles() = %q, want %q", got, want)
	}
}

func TestSearchUdevFiles_FoundV0Tag(t *testing.T) {
	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, "c13:66")
	content := "G:power-switch\n"
	if err := os.WriteFile(filePath, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write test udev file: %v", err)
	}

	got, err := searchUdevFiles(tempDir, "c13:*")
	if err != nil {
		t.Fatalf("searchUdevFiles() error = %v", err)
	}

	// Minor 66: 66 - 64 = 2 -> /dev/input/event2
	want := "/dev/input/event2"
	if got != want {
		t.Errorf("searchUdevFiles() = %q, want %q", got, want)
	}
}

func TestSearchUdevFiles_NotFound(t *testing.T) {
	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, "c13:65")
	content := "Q:keyboard\n"
	if err := os.WriteFile(filePath, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write test udev file: %v", err)
	}

	_, err := searchUdevFiles(tempDir, "c13:*")
	if err == nil {
		t.Fatal("searchUdevFiles() succeeded, expected error when tag is missing")
	}
}

func TestSearchUdevFiles_MultipleFilesSkipsNonMatching(t *testing.T) {
	tempDir := t.TempDir()

	// File 1: non-matching tag
	if err := os.WriteFile(filepath.Join(tempDir, "c13:64"), []byte("Q:keyboard\n"), 0644); err != nil {
		t.Fatalf("failed to write test file 1: %v", err)
	}
	// File 2: invalid minor below offset (63 < 64)
	if err := os.WriteFile(filepath.Join(tempDir, "c13:63"), []byte("Q:power-switch\n"), 0644); err != nil {
		t.Fatalf("failed to write test file 2: %v", err)
	}
	// File 3: malformed non-numeric minor
	if err := os.WriteFile(filepath.Join(tempDir, "c13:abc"), []byte("Q:power-switch\n"), 0644); err != nil {
		t.Fatalf("failed to write test file 3: %v", err)
	}
	// File 4: valid matching power switch
	if err := os.WriteFile(filepath.Join(tempDir, "c13:67"), []byte("Q:power-switch\n"), 0644); err != nil {
		t.Fatalf("failed to write test file 4: %v", err)
	}

	got, err := searchUdevFiles(tempDir, "c13:*")
	if err != nil {
		t.Fatalf("searchUdevFiles() error = %v", err)
	}

	// Minor 67: 67 - 64 = 3 -> /dev/input/event3
	want := "/dev/input/event3"
	if got != want {
		t.Errorf("searchUdevFiles() = %q, want %q", got, want)
	}
}

func TestFindPowerButtonIn_PrioritizesUdevC13(t *testing.T) {
	udevTempDir := t.TempDir()
	procTempDir := t.TempDir()

	udevFile := filepath.Join(udevTempDir, "c13:64")
	if err := os.WriteFile(udevFile, []byte("Q:power-switch\n"), 0644); err != nil {
		t.Fatalf("failed to write test udev file: %v", err)
	}

	procFile := filepath.Join(procTempDir, "devices")
	procContent := `I: Bus=0019 Vendor=0000 Product=0001 Version=0000
N: Name="Power Button"
H: Handlers=kbd event5
`
	if err := os.WriteFile(procFile, []byte(procContent), 0644); err != nil {
		t.Fatalf("failed to write test procfs file: %v", err)
	}

	got, err := findPowerButtonIn(udevTempDir, procFile, logging.SimpleLogger())
	if err != nil {
		t.Fatalf("findPowerButtonIn() error = %v", err)
	}

	want := "/dev/input/event0"
	if got != want {
		t.Errorf("findPowerButtonIn() = %q, want %q (should prioritize udev over procfs)", got, want)
	}
}

func TestFindPowerButtonIn_FallsBackToUdevWildcard(t *testing.T) {
	udevTempDir := t.TempDir()
	procTempDir := t.TempDir()

	// Name does not match "c13:*", but matches "*"
	udevFile := filepath.Join(udevTempDir, "input0:68")
	if err := os.WriteFile(udevFile, []byte("Q:power-switch\n"), 0644); err != nil {
		t.Fatalf("failed to write test udev file: %v", err)
	}

	procFile := filepath.Join(procTempDir, "devices")
	procContent := `I: Bus=0019 Vendor=0000 Product=0001 Version=0000
N: Name="Power Button"
H: Handlers=kbd event5
`
	if err := os.WriteFile(procFile, []byte(procContent), 0644); err != nil {
		t.Fatalf("failed to write test procfs file: %v", err)
	}

	got, err := findPowerButtonIn(udevTempDir, procFile, logging.SimpleLogger())
	if err != nil {
		t.Fatalf("findPowerButtonIn() error = %v", err)
	}

	// Minor 68: 68 - 64 = 4 -> /dev/input/event4
	want := "/dev/input/event4"
	if got != want {
		t.Errorf("findPowerButtonIn() = %q, want %q", got, want)
	}
}

func TestFindPowerButtonIn_FallsBackToProcfs(t *testing.T) {
	emptyUdevDir := t.TempDir()
	procTempDir := t.TempDir()

	procFile := filepath.Join(procTempDir, "devices")
	procContent := `I: Bus=0019 Vendor=0000 Product=0001 Version=0000
N: Name="Power Button"
H: Handlers=kbd event5
`
	if err := os.WriteFile(procFile, []byte(procContent), 0644); err != nil {
		t.Fatalf("failed to write test procfs file: %v", err)
	}

	got, err := findPowerButtonIn(emptyUdevDir, procFile, logging.SimpleLogger())
	if err != nil {
		t.Fatalf("findPowerButtonIn() error = %v", err)
	}

	want := "/dev/input/event5"
	if got != want {
		t.Errorf("findPowerButtonIn() = %q, want %q", got, want)
	}
}

func TestFindPowerButtonIn_CompleteFailureReturnsError(t *testing.T) {
	emptyUdevDir := t.TempDir()
	procTempDir := t.TempDir()

	procFile := filepath.Join(procTempDir, "devices")
	procContent := `I: Bus=0011 Vendor=0001 Product=0001 Version=ab41
N: Name="AT Translated Set 2 keyboard"
H: Handlers=kbd event0
`
	if err := os.WriteFile(procFile, []byte(procContent), 0644); err != nil {
		t.Fatalf("failed to write test procfs file: %v", err)
	}

	_, err := findPowerButtonIn(emptyUdevDir, procFile, logging.SimpleLogger())
	if err == nil {
		t.Fatal("findPowerButtonIn() succeeded, expected error when device is nowhere to be found")
	}
}
