package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

type exitScriptEnv struct {
	binDir    string
	dbDir     string
	logFile   string
	sleepPath string
}

func (e *exitScriptEnv) writeStub(t *testing.T, name, body string) {
	t.Helper()
	p := filepath.Join(e.binDir, name)
	if err := os.WriteFile(p, []byte(body), 0755); err != nil {
		t.Fatalf("os.WriteFile(%q) failed: %v", p, err)
	}
}

func newExitScriptEnv(t *testing.T, fluentBitActive bool, cursor string) *exitScriptEnv {
	t.Helper()

	sleepPath, err := exec.LookPath("sleep")
	if err != nil {
		t.Fatalf("exec.LookPath(\"sleep\") failed: %v", err)
	}

	dir := t.TempDir()
	binDir := filepath.Join(dir, "bin")
	dbDir := filepath.Join(dir, "db")
	logFile := filepath.Join(dir, "calls.log")

	if err := os.MkdirAll(binDir, 0755); err != nil {
		t.Fatalf("os.MkdirAll(%q) failed: %v", binDir, err)
	}
	if err := os.MkdirAll(dbDir, 0755); err != nil {
		t.Fatalf("os.MkdirAll(%q) failed: %v", dbDir, err)
	}

	env := &exitScriptEnv{
		binDir:    binDir,
		dbDir:     dbDir,
		logFile:   logFile,
		sleepPath: sleepPath,
	}

	env.writeStub(t, "shutdown", fmt.Sprintf(`#!/bin/bash
echo "shutdown $*" >> %q
`, logFile))

	activeCode := 3
	if fluentBitActive {
		activeCode = 0
	}
	env.writeStub(t, "systemctl", fmt.Sprintf(`#!/bin/bash
echo "systemctl $*" >> %q
if [[ "$1" == "is-active" ]]; then
  exit %d
fi
`, logFile, activeCode))

	env.writeStub(t, "journalctl", fmt.Sprintf(`#!/bin/bash
for arg in "$@"; do
  if [[ "${arg}" == --cursor-file=* ]]; then
    cursor_path="${arg#--cursor-file=}"
    if [[ -n %q ]]; then
      printf '%%s\n' %q > "${cursor_path}"
    fi
    echo "journalctl cursor $1" >> %q
    exit 0
  fi
done
echo "journalctl $*" >> %q
`, cursor, cursor, logFile, logFile))

	return env
}

func (e *exitScriptEnv) run(ctx context.Context, t *testing.T, extraEnv ...string) []string {
	t.Helper()

	cmd := exec.CommandContext(ctx, "bash", "../image/exit_script.sh")
	env := []string{
		"PATH=" + e.binDir + ":" + os.Getenv("PATH"),
		"FLUENTBIT_DB_DIR=" + e.dbDir,
		"DRAIN_TIMEOUT_SEC=1",
	}
	cmd.Env = append(env, extraEnv...)

	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("exit_script.sh failed: %v\noutput: %s", err, out)
	}

	data, err := os.ReadFile(e.logFile)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatalf("os.ReadFile(%q) failed: %v", e.logFile, err)
	}
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" {
		return nil
	}
	return strings.Split(trimmed, "\n")
}

func TestExitScript_DelayedActions(t *testing.T) {
	testCases := []struct {
		name       string
		exitStatus string
		wantCalls  []string
	}{
		{
			name:       "success_rc",
			exitStatus: "0",
			wantCalls:  []string{"shutdown --poweroff +2"},
		},
		{
			name:       "fail_rc",
			exitStatus: "1",
			wantCalls:  []string{"shutdown --poweroff +2"},
		},
		{
			name:       "panic_exit",
			exitStatus: "2",
			wantCalls:  []string{"shutdown --poweroff +2"},
		},
		{
			name:       "reboot_rc",
			exitStatus: "3",
			wantCalls:  []string{"shutdown --reboot +2"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			env := newExitScriptEnv(t, true, "")
			got := env.run(t.Context(), t, "EXIT_CODE=exited", "EXIT_STATUS="+tc.exitStatus)
			if diff := cmp.Diff(tc.wantCalls, got); diff != "" {
				t.Errorf("exit_script.sh(EXIT_STATUS=%q) calls mismatch (-want +got):\n%s", tc.exitStatus, diff)
			}
		})
	}
}

func TestExitScript_IgnoresNonActionableExits(t *testing.T) {
	testCases := []struct {
		name     string
		extraEnv []string
	}{
		{
			name:     "hold_rc",
			extraEnv: []string{"EXIT_CODE=exited", "EXIT_STATUS=4"},
		},
		{
			name:     "killed_by_signal",
			extraEnv: []string{"EXIT_CODE=killed", "EXIT_STATUS=TERM"},
		},
		{
			name:     "empty_exit_status",
			extraEnv: []string{"EXIT_CODE=exited", "EXIT_STATUS="},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			env := newExitScriptEnv(t, true, "")
			got := env.run(t.Context(), t, tc.extraEnv...)
			if len(got) != 0 {
				t.Errorf("exit_script.sh(%v) ran commands %v, want none", tc.extraEnv, got)
			}
		})
	}
}

func TestExitScript_HostShutdownDrainsFluentBitAndPowersOff(t *testing.T) {
	cursor := "s=abc123;i=456;b=def789;m=1;t=2;x=3"
	env := newExitScriptEnv(t, true, cursor)

	stagedDB := filepath.Join(t.TempDir(), "container-runner.log.db")
	dbFile := filepath.Join(env.dbDir, "container-runner.log.db")
	dbContents := append([]byte{0x00, 0x01, 0x02}, []byte("SQLite\x00"+cursor+"\x00")...)
	if err := os.WriteFile(stagedDB, dbContents, 0644); err != nil {
		t.Fatalf("os.WriteFile(%q) failed: %v", stagedDB, err)
	}
	env.writeStub(t, "sleep", fmt.Sprintf(`#!/bin/bash
echo "sleep $*" >> %q
cp %q %q
exec %q "$@"
`, env.logFile, stagedDB, dbFile, env.sleepPath))

	got := env.run(t.Context(), t, "DRAIN_TIMEOUT_SEC=10", "EXIT_CODE=exited", "EXIT_STATUS=5")
	want := []string{
		"journalctl --sync",
		"systemctl is-active --quiet fluent-bit.service",
		"journalctl cursor _SYSTEMD_UNIT=container-runner.service",
		"sleep 0.2",
		"systemctl stop fluent-bit.service",
		"systemctl --no-block poweroff",
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("exit_script.sh calls mismatch (-want +got):\n%s", diff)
	}
}

func TestExitScript_HostShutdownSkipsDrainWhenFluentBitInactive(t *testing.T) {
	env := newExitScriptEnv(t, false, "s=unused")

	got := env.run(t.Context(), t, "EXIT_CODE=exited", "EXIT_STATUS=5")
	want := []string{
		"journalctl --sync",
		"systemctl is-active --quiet fluent-bit.service",
		"systemctl --no-block poweroff",
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("exit_script.sh calls mismatch (-want +got):\n%s", diff)
	}
}

func TestExitScript_HostShutdownPowersOffAfterDrainTimeout(t *testing.T) {
	env := newExitScriptEnv(t, true, "s=never-ingested")
	sleptFile := filepath.Join(t.TempDir(), "slept")
	env.writeStub(t, "sleep", fmt.Sprintf(`#!/bin/bash
touch %q
exec %q "$@"
`, sleptFile, env.sleepPath))

	got := env.run(t.Context(), t, "EXIT_CODE=exited", "EXIT_STATUS=5")
	want := []string{
		"journalctl --sync",
		"systemctl is-active --quiet fluent-bit.service",
		"journalctl cursor _SYSTEMD_UNIT=container-runner.service",
		"systemctl stop fluent-bit.service",
		"systemctl --no-block poweroff",
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("exit_script.sh calls mismatch (-want +got):\n%s", diff)
	}
	if _, err := os.Stat(sleptFile); err != nil {
		t.Errorf("exit_script.sh did not poll before drain timeout: os.Stat(%q) = %v", sleptFile, err)
	}
}
