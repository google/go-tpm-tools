//go:build linux
// +build linux

package cmd

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/google/go-tpm/tpmutil"
)

// fakeTitan is a fake transport.TPMCloser returning a canned response.
type fakeTitan struct {
	lastCommand []byte
	response    []byte
	sendErr     error
	closed      bool
}

func (f *fakeTitan) Send(input []byte) ([]byte, error) {
	f.lastCommand = append([]byte(nil), input...)
	if f.sendErr != nil {
		return nil, f.sendErr
	}
	return f.response, nil
}

func (f *fakeTitan) Close() error {
	f.closed = true
	return nil
}

func TestIPMITPMRoundTrip(t *testing.T) {
	// A minimal, well-formed TPM2 response: tag, size, response code.
	want := []byte{0x80, 0x01, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x00, 0xab, 0xcd}
	fake := &fakeTitan{response: want}
	rwc := &ipmiTPM{tpm: fake}

	cmd := []byte{0x80, 0x01, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x01, 0x7a}
	// tpmutil.RunCommandRaw performs the same single Write/Read sequence used by
	// all legacy gotpm commands, so it exercises the adapter end to end.
	got, err := tpmutil.RunCommandRaw(rwc, cmd)
	if err != nil {
		t.Fatalf("RunCommandRaw() returned error: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("RunCommandRaw() = %x, want %x", got, want)
	}
	if !bytes.Equal(fake.lastCommand, cmd) {
		t.Errorf("TPM received %x, want %x", fake.lastCommand, cmd)
	}
}

func TestIPMITPMPartialReads(t *testing.T) {
	want := []byte{1, 2, 3, 4, 5}
	rwc := &ipmiTPM{tpm: &fakeTitan{response: want}}

	if _, err := rwc.Write([]byte{0xff}); err != nil {
		t.Fatalf("Write() returned error: %v", err)
	}

	var got []byte
	buf := make([]byte, 2)
	for {
		n, err := rwc.Read(buf)
		got = append(got, buf[:n]...)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("Read() returned error: %v", err)
		}
	}
	if !bytes.Equal(got, want) {
		t.Errorf("read %x, want %x", got, want)
	}
}

func TestIPMITPMWriteError(t *testing.T) {
	sendErr := errors.New("ipmi failure")
	rwc := &ipmiTPM{tpm: &fakeTitan{sendErr: sendErr}}

	if _, err := rwc.Write([]byte{0xff}); !errors.Is(err, sendErr) {
		t.Errorf("Write() error = %v, want %v", err, sendErr)
	}
}

func TestIPMITPMClose(t *testing.T) {
	fake := &fakeTitan{}
	rwc := &ipmiTPM{tpm: fake}
	if err := rwc.Close(); err != nil {
		t.Fatalf("Close() returned error: %v", err)
	}
	if !fake.closed {
		t.Error("Close() did not close the underlying TPM transport")
	}
}

// TestIPMIPathRouting checks which --tpm-path values are routed to the IPMI
// transport, and that unsupported IPMI devices are rejected.
func TestIPMIPathRouting(t *testing.T) {
	for _, tc := range []struct {
		path   string
		isIPMI bool
	}{
		{path: "", isIPMI: false},
		{path: "/dev/tpmrm0", isIPMI: false},
		{path: "/dev/tpm0", isIPMI: false},
		{path: "/dev/ipmi0", isIPMI: true},
		{path: "/dev/ipmi1", isIPMI: true},
	} {
		if got := strings.HasPrefix(tc.path, ipmiPathPrefix); got != tc.isIPMI {
			t.Errorf("path %q routed to IPMI = %t, want %t", tc.path, got, tc.isIPMI)
		}
	}

	// Only /dev/ipmi0 is supported, and unsupported devices must fail before
	// any attempt to talk to the hardware.
	if _, err := openIPMI("/dev/ipmi1"); err == nil {
		t.Error("openIPMI(\"/dev/ipmi1\") returned nil error, want error")
	}
}
