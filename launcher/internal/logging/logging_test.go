package logging

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"reflect"
	"strings"
	"testing"

	clogging "cloud.google.com/go/logging"
	"github.com/google/go-cmp/cmp"
	mrpb "google.golang.org/genproto/googleapis/api/monitoredres"
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

// testCLogger implements the cLogger interface.
type testCLogger struct {
	log clogging.Entry
}

func (c *testCLogger) Log(entry clogging.Entry) {
	// Cloud Logging sends multiple messages - append everything together for simplicity.
	c.log = entry
}

func (c *testCLogger) Flush() error { return nil }

// testSLogWriter implements the io.Writer interface.
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
	testResource := &mrpb.MonitoredResource{
		Type: "gce_instance",
		Labels: map[string]string{
			"instance_id": "1234",
			"project_id":  "not-a-real-project",
			"zone":        "us-central1-c",
		},
	}

	// Redirect loggers to buffers.
	cloudLogger := &testCLogger{}
	serialLogs := &testSLogWriter{}

	testLogger := &logger{
		cloudLogger:  cloudLogger,
		serialLogger: slog.New(slog.NewTextHandler(serialLogs, nil)),
		resource:     testResource,

		instanceName: "test-instance",
	}

	testMsg := "test message"
	testPayload := payload{
		"key1": "value1",
		"key2": 2,
		"key3": false,
	}

	testLogger.writeLog(clogging.Info, testMsg, toArgs(testPayload)...)

	if err := serialLogs.checkLogContains(testMsg, testPayload); err != nil {
		t.Errorf("Error validating Serial Log contents: %v", err)
	}

	if err := serialLogs.checkLogLevel(slog.LevelInfo); err != nil {
		t.Errorf("Error validating Serial Log level: %v", err)
	}

	// Add message and hostnames values to expected payload.
	testPayload[payloadMessageKey] = testMsg
	testPayload[payloadHostnameKey] = testLogger.instanceName

	if !cmp.Equal(cloudLogger.log.Payload, testPayload) {
		t.Errorf("Did not get expected payload in cloud logs: got %v, want %v", cloudLogger.log.Payload, testPayload)
	}

	if cloudLogger.log.Severity != clogging.Info {
		t.Errorf("Did not get expected severity in cloud logs: got %v, want %v", cloudLogger.log.Severity, clogging.Info)
	}

	// Compare monitored resource.
	if cloudLogger.log.Resource.Type != testResource.Type {
		t.Errorf("Did not get expected monitored resource tyoe: got %v, want %v", cloudLogger.log.Resource.Type, testResource.Type)
	}

	if !cmp.Equal(cloudLogger.log.Resource.Labels, testResource.Labels) {
		t.Errorf("Did not get expected monitored resource labels in cloud logs: got %v, want %v", cloudLogger.log.Resource.Labels, testResource.Labels)
	}
}

func TestLogFunctions(t *testing.T) {
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
			cloudLogs := &testCLogger{}
			serialLogs := &testSLogWriter{}

			testLogger := &logger{
				cloudLogger:  cloudLogs,
				serialLogger: slog.New(slog.NewTextHandler(serialLogs, nil)),
				instanceName: "test-instance",
			}

			tc.logFunc(testLogger, msg)

			expectedPayload := payload{
				"MESSAGE":   msg,
				"_HOSTNAME": testLogger.instanceName,
			}

			if cloudLogs.log.Severity != tc.cloud_severity {
				t.Errorf("Cloud logs did not contain expected severity: got %v, want %v", cloudLogs.log.Severity, tc.cloud_severity)
			}

			if !cmp.Equal(cloudLogs.log.Payload, expectedPayload) {
				t.Errorf("Cloud logs did not contain expected payload: got %v, want %v", cloudLogs.log.Payload, expectedPayload)
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
