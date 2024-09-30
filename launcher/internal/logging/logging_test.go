package logging

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"reflect"
	"strings"
	"testing"

	clogging "cloud.google.com/go/logging"
)

func toArgs(pl payload) []any {
	args := []any{}
	for k, v := range pl {
		args = append(args, k)
		args = append(args, v)
	}

	return args
}

func TestAddArgs(t *testing.T) {
	testcases := []struct {
		name     string
		args     []any
		expected payload
	}{
		{
			name: "regular payload",
			args: []any{"key1", 1, "key2", "two", "key3", false},
			expected: payload{
				"key1": 1,
				"key2": "two",
				"key3": false,
			},
		},
		{
			name: "missing value at end",
			args: []any{"key1", 1, "key2", "two", "key3"},
			expected: payload{
				"key1": 1,
				"key2": "two",
				"key3": "",
			},
		},
		{
			name:     "empty args",
			args:     []any{},
			expected: payload{},
		},
		{
			name: "incompatible key omitted",
			args: []any{"key1", 1, 2, "two", "key3", false},
			expected: payload{
				"key1": 1,
				"key3": false,
			},
		},
		{
			name: "single arg, valid key",
			args: []any{"key1"},
			expected: payload{
				"key1": "",
			},
		},
		{
			name:     "single arg, not valid key",
			args:     []any{true},
			expected: payload{},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			pl := payload{}
			addArgs(pl, tc.args)

			if !reflect.DeepEqual(pl, tc.expected) {
				t.Errorf("addArgs did not produce expected payload: got %v, want %v", pl, tc.expected)
			}
		})
	}
}

type testCLogWriter struct {
	log []byte
}

func (c *testCLogWriter) Write(p []byte) (n int, err error) {
	// Cloud Logging sends multiple messages - append everything together for simplicity.
	c.log = append(c.log, p...)
	return 0, nil
}

func (c *testCLogWriter) checkLogContains(msg string, payloadJSON []byte) error {
	if len(c.log) == 0 {
		return errors.New("Cloud log is empty.")

	}

	if !bytes.Contains(c.log, []byte(msg)) {
		return fmt.Errorf("Log did not contain expected message: got %s, want \"%s\"", c.log, msg)
	}

	if len(payloadJSON) > 0 {
		// Trim start/end brackets.
		expected := payloadJSON[1 : len(payloadJSON)-1]

		if !bytes.Contains(c.log, expected) {
			return fmt.Errorf("Log did not contain expected fields: got %s, want %s", c.log, expected)
		}
	}

	return nil
}

func (c *testCLogWriter) checkLogSeverity(sev clogging.Severity) error {
	expected := fmt.Sprintf("\"severity\":\"%v\"", strings.ToUpper(sev.String()))

	if !bytes.Contains(c.log, []byte(expected)) {
		return fmt.Errorf("Log did not contain expected severity field %v: %s", expected, c.log)
	}

	return nil
}

type testSLogWriter struct {
	t   *testing.T
	log []byte
}

func (s *testSLogWriter) Write(p []byte) (n int, err error) {
	s.log = p

	return 0, nil
}

func (s *testSLogWriter) checkLogContains(msg string, pl payload) error {
	if len(s.log) == 0 {
		return errors.New("Serial log is empty.")
	}

	if !bytes.Contains(s.log, []byte(msg)) {
		return fmt.Errorf("Log did not contain expected message: got %s, want \"%s\"", s.log, msg)
	}

	if len(pl) > 0 {
		strLogs := string(s.log)

		// Check that each payload value is present in the format key=value.
		for k, v := range pl {
			format := "%v=%v"
			if vStr, ok := v.(string); ok && strings.Contains(vStr, " ") {
				format = "%v=\"%v\""
			}

			expectedStr := fmt.Sprintf(format, k, v)
			if !strings.Contains(strLogs, expectedStr) {
				return fmt.Errorf("Logs expected to contain \"%s\", got \"%s\"", expectedStr, strLogs)
			}
		}
	}

	return nil
}

func (s *testSLogWriter) checkLogLevel(level slog.Level) error {
	expected := "level=" + level.String()

	if !strings.Contains(string(s.log), expected) {
		return fmt.Errorf("Log did not contain expected level %v: %v", expected, string(s.log))
	}

	return nil
}

func TestWriteLog(t *testing.T) {
	client, err := clogging.NewClient(context.Background(), "test-project")
	if err != nil {
		t.Fatalf("Error creating cloud logging client: %v", err)
	}
	t.Cleanup(func() { client.Close() })

	// Redirect loggers to buffers.
	cloudLogs := &testCLogWriter{}
	serialLogs := &testSLogWriter{}

	testLogger := &logger{
		cloudLogger:  client.Logger("test-log", clogging.RedirectAsJSON(cloudLogs)),
		serialLogger: slog.New(slog.NewTextHandler(serialLogs, nil)),

		instanceName: "test-instance",
		cloudClient:  client,
	}

	testMsg := "test message"
	testPayload := payload{
		"key1": "value1",
		"key2": 2,
		"key3": false,
	}

	testLogger.writeLog(clogging.Info, testMsg, toArgs(testPayload)...)

	expectedJSON, err := json.Marshal(testPayload)
	if err != nil {
		t.Fatalf("Failed to marshal expected payload: %v", err)
	}

	if err := cloudLogs.checkLogContains(testMsg, expectedJSON); err != nil {
		t.Errorf("Error validating Cloud Log contents: %v", err)
	}

	if err := cloudLogs.checkLogSeverity(clogging.Info); err != nil {
		t.Errorf("Error validating Cloud Log severity: %v", err)
	}

	if err := serialLogs.checkLogContains(testMsg, testPayload); err != nil {
		t.Errorf("Error validating Serial Log contents: %v", err)
	}

	if err := serialLogs.checkLogLevel(slog.LevelInfo); err != nil {
		t.Errorf("Error validating Serial Log level: %v", err)
	}
}

func TestLogFunctions(t *testing.T) {
	client, err := clogging.NewClient(context.Background(), "test-project")
	if err != nil {
		t.Fatalf("Error creating cloud logging client: %v", err)
	}
	t.Cleanup(func() { client.Close() })

	testcases := []struct {
		name           string
		cloud_severity clogging.Severity
		serial_level   slog.Level
		logFunc        func(lgr *logger, msg string)
	}{
		{
			name:           "logger.Info",
			cloud_severity: clogging.Info,
			serial_level:   slog.LevelInfo,
			logFunc: func(lgr *logger, msg string) {
				lgr.Info(msg)
			},
		},
		{
			name:           "logger.Warn",
			cloud_severity: clogging.Warning,
			serial_level:   slog.LevelWarn,
			logFunc: func(lgr *logger, msg string) {
				lgr.Warn(msg)
			},
		},
		{
			name:           "logger.Error",
			cloud_severity: clogging.Error,
			serial_level:   slog.LevelError,
			logFunc: func(lgr *logger, msg string) {
				lgr.Error(msg)
			},
		},
	}

	msg := "test message"
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {

			// Redirect loggers to buffers.
			cloudLogs := &testCLogWriter{}
			serialLogs := &testSLogWriter{}

			testLogger := &logger{
				cloudLogger:  client.Logger("test-log", clogging.RedirectAsJSON(cloudLogs)),
				serialLogger: slog.New(slog.NewTextHandler(serialLogs, nil)),
				instanceName: "test-instance",
				cloudClient:  client,
			}

			tc.logFunc(testLogger, msg)

			if err := cloudLogs.checkLogContains(msg, []byte{}); err != nil {
				t.Errorf("Error validating Cloud Log contents: %v", err)
			}

			if err := cloudLogs.checkLogSeverity(tc.cloud_severity); err != nil {
				t.Errorf("Error validating Cloud Log severity: %v", err)
			}

			if err := serialLogs.checkLogContains(msg, payload{}); err != nil {
				t.Errorf("Error validating Serial Log contents: %v", err)
			}

			if err := serialLogs.checkLogLevel(tc.serial_level); err != nil {
				t.Errorf("Error validating Serial Log level: %v", err)
			}
		})
	}
}
