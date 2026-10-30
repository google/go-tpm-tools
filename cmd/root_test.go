package cmd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"runtime"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-tpm-tools/client"
	"github.com/spf13/cobra"
)

// extTPMWrapper is designed to wrap an external TPM to provide some overriding
// functions.
type extTPMWrapper struct {
	io.ReadWriter
}

// Close is no-op for extTPMWrapper to prevent it closing the underlying simulator.
func (et extTPMWrapper) Close() error {
	return nil
}

// EventLog is a workaround so the caller can call the underlying EventLogGetter function
// of the underlying TPM.
func (et extTPMWrapper) EventLog() ([]byte, error) {
	return client.GetEventLog(et.ReadWriter)
}

// testTPM returns a TPM opener for tests. If tpm is nil, the opener returns an
// error.
func testTPM(tpm io.ReadWriter) func(string) (io.ReadWriteCloser, error) {
	return func(string) (io.ReadWriteCloser, error) {
		if tpm == nil {
			return nil, errors.New("test did not provide a TPM")
		}
		return extTPMWrapper{tpm}, nil
	}
}

// testHTTPClient returns an HTTP client factory for tests. If client is nil,
// the factory returns an error.
func testHTTPClient(client *http.Client) func(context.Context) (*http.Client, error) {
	return func(context.Context) (*http.Client, error) {
		if client == nil {
			return nil, errors.New("test did not provide an HTTP client")
		}
		return client, nil
	}
}

// execute runs gotpm with args. tpm can be nil if the command does not open a
// TPM.
func execute(args []string, tpm io.ReadWriter) error {
	root := newGotpmCmd(testTPM(tpm), testHTTPClient(nil))
	root.SetArgs(args)
	return root.Execute()
}

// executeOutput runs gotpm with args and returns what the command wrote to its
// standard output.
func executeOutput(args []string, tpm io.ReadWriter) ([]byte, error) {
	var out bytes.Buffer
	root := newGotpmCmd(testTPM(tpm), testHTTPClient(nil))
	root.SetArgs(args)
	root.SetOut(&out)
	err := root.Execute()
	return out.Bytes(), err
}

func parseRootFlags(args []string) (rootOptions, error) {
	var flags rootFlags
	cmd := &cobra.Command{}
	addRootFlags(cmd, &flags)
	if err := cmd.ParseFlags(args); err != nil {
		return rootOptions{}, err
	}
	return flags.parse()
}

func TestParseRootFlagsDefaults(t *testing.T) {
	got, err := parseRootFlags(nil)
	if err != nil {
		t.Fatalf("parseRootFlags(nil) = %v, want nil", err)
	}
	want := rootOptions{output: outputNormal}
	if diff := cmp.Diff(want, got, cmp.AllowUnexported(rootOptions{})); diff != "" {
		t.Errorf("parseRootFlags(nil) returned unexpected diff (-want +got):\n%s", diff)
	}
}

func TestParseRootFlagsQuiet(t *testing.T) {
	args := []string{"--quiet"}
	got, err := parseRootFlags(args)
	if err != nil {
		t.Fatalf("parseRootFlags(%q) = %v, want nil", args, err)
	}
	if got.output != outputQuiet {
		t.Errorf("parseRootFlags(%q).output = %v, want %v", args, got.output, outputQuiet)
	}
}

func TestParseRootFlagsVerbose(t *testing.T) {
	args := []string{"--verbose"}
	got, err := parseRootFlags(args)
	if err != nil {
		t.Fatalf("parseRootFlags(%q) = %v, want nil", args, err)
	}
	if got.output != outputVerbose {
		t.Errorf("parseRootFlags(%q).output = %v, want %v", args, got.output, outputVerbose)
	}
}

func TestParseRootFlagsRejectsQuietAndVerbose(t *testing.T) {
	args := []string{"--quiet", "--verbose"}
	if _, err := parseRootFlags(args); !errors.Is(err, errQuietAndVerbose) {
		t.Errorf("parseRootFlags(%q) = %v, want %v", args, err, errQuietAndVerbose)
	}
}

func TestRootRejectsQuietAndVerbose(t *testing.T) {
	args := []string{"--quiet", "--verbose", "flush", "all"}
	if err := execute(args, nil); !errors.Is(err, errQuietAndVerbose) {
		t.Errorf("execute(%q) = %v, want %v", args, err, errQuietAndVerbose)
	}
}

func TestRootForwardsTPMPath(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not define --tpm-path")
	}
	errStop := errors.New("stop")
	var gotPath string
	root := newGotpmCmd(func(path string) (io.ReadWriteCloser, error) {
		gotPath = path
		return nil, errStop
	}, testHTTPClient(nil))
	args := []string{"--tpm-path", "/dev/tpm99", "flush", "all"}
	root.SetArgs(args)
	if err := root.Execute(); !errors.Is(err, errStop) {
		t.Fatalf("Execute(%q) = %v, want %v", args, err, errStop)
	}
	if gotPath != "/dev/tpm99" {
		t.Errorf("tpmOpener path = %q, want %q", gotPath, "/dev/tpm99")
	}
}

func TestRootMessageOutputDefault(t *testing.T) {
	var buf bytes.Buffer
	o := &gotpmOptions{out: func() io.Writer { return &buf }}
	fmt.Fprint(o.messageOutput(), "hello")
	if buf.String() != "hello" {
		t.Errorf("messageOutput() wrote %q, want %q", buf.String(), "hello")
	}
}

func TestRootMessageOutputQuiet(t *testing.T) {
	var buf bytes.Buffer
	o := &gotpmOptions{root: rootOptions{output: outputQuiet}, out: func() io.Writer { return &buf }}
	fmt.Fprint(o.messageOutput(), "hello")
	if buf.Len() != 0 {
		t.Errorf("messageOutput() with quiet wrote %q, want empty", buf.String())
	}
}

func TestRootDebugOutputDefault(t *testing.T) {
	var buf bytes.Buffer
	o := &gotpmOptions{out: func() io.Writer { return &buf }}
	fmt.Fprint(o.debugOutput(), "debug")
	if buf.Len() != 0 {
		t.Errorf("debugOutput() wrote %q, want empty", buf.String())
	}
}

func TestRootDebugOutputVerbose(t *testing.T) {
	var buf bytes.Buffer
	o := &gotpmOptions{root: rootOptions{output: outputVerbose}, out: func() io.Writer { return &buf }}
	fmt.Fprint(o.debugOutput(), "debug")
	if buf.String() != "debug" {
		t.Errorf("debugOutput() with verbose wrote %q, want %q", buf.String(), "debug")
	}
}
