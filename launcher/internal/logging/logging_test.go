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
	log []byte
}

func (s *testSLogWriter) Write(p []byte) (n int, err error) {
	s.log = p

	return 0, nil
}

func (s *testSLogWriter) checkLogContains(msg string, pl payload) error {
	if len(s.log) == 0 {
		return errors.New("serial log is empty")
	}

	if !bytes.Contains(s.log, []byte(msg)) {
		return fmt.Errorf("log did not contain expected message: got %s, want \"%s\"", s.log, msg)
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
				return fmt.Errorf("logs expected to contain \"%s\", got \"%s\"", expectedStr, strLogs)
			}
		}
	}

	return nil
}

func (s *testSLogWriter) checkLogLevel(level slog.Level) error {
	expected := "level=" + level.String()

	if !strings.Contains(string(s.log), expected) {
		return fmt.Errorf("log did not contain expected level %v: %v", expected, string(s.log))
	}

	return nil
}

func TestCloudLogger(t *testing.T) {
	testResource := &mrpb.MonitoredResource{
		Type: "gce_instance",
		Labels: map[string]string{
			"instance_id": "1234",
			"project_id":  "not-a-real-project",
			"zone":        "us-central1-c",
		},
	}

	cloudC := &testCLogger{}
	cl := &cloudLogger{
		cloudLogger:  cloudC,
		resource:     testResource,
		instanceName: "test-instance",
	}

	testMsg := "test message"
	testPayload := payload{
		"key1": "value1",
		"key2": 2,
		"key3": false,
	}

	cl.Log(clogging.Info, testMsg, toArgs(testPayload)...)

	// Add message and hostnames values to expected payload.
	testPayload[payloadMessageKey] = testMsg
	testPayload[payloadInstanceNameKey] = cl.instanceName

	if !cmp.Equal(cloudC.log.Payload, testPayload) {
		t.Errorf("Did not get expected payload in cloud logs: got %v, want %v", cloudC.log.Payload, testPayload)
	}

	if cloudC.log.Severity != clogging.Info {
		t.Errorf("Did not get expected severity in cloud logs: got %v, want %v", cloudC.log.Severity, clogging.Info)
	}

	// Compare monitored resource.
	if cloudC.log.Resource.Type != testResource.Type {
		t.Errorf("Did not get expected monitored resource tyoe: got %v, want %v", cloudC.log.Resource.Type, testResource.Type)
	}

	if !cmp.Equal(cloudC.log.Resource.Labels, testResource.Labels) {
		t.Errorf("Did not get expected monitored resource labels in cloud logs: got %v, want %v", cloudC.log.Resource.Labels, testResource.Labels)
	}
}

func TestSerialLogger(t *testing.T) {
	serialLogs := &testSLogWriter{}
	sl := &serialLogger{
		slg: slog.New(slog.NewTextHandler(serialLogs, nil)),
	}

	testMsg := "test message"
	testPayload := payload{
		"key1": "value1",
		"key2": 2,
		"key3": false,
	}

	sl.Log(clogging.Info, testMsg, toArgs(testPayload)...)

	if err := serialLogs.checkLogContains(testMsg, testPayload); err != nil {
		t.Errorf("Error validating Serial Log contents: %v", err)
	}

	if err := serialLogs.checkLogLevel(slog.LevelInfo); err != nil {
		t.Errorf("Error validating Serial Log level: %v", err)
	}
}

func TestDualLogger(t *testing.T) {
	cloudC := &testCLogger{}
	cl := &cloudLogger{
		cloudLogger:  cloudC,
		resource:     &mrpb.MonitoredResource{},
		instanceName: "test-instance",
	}

	serialLogs := &testSLogWriter{}
	sl := &serialLogger{
		slg: slog.New(slog.NewTextHandler(serialLogs, nil)),
	}

	dLogger := DualLogger(cl, sl)

	testMsg := "test message"
	dLogger.Log(clogging.Info, testMsg)

	if cloudC.log.Severity != clogging.Info {
		t.Errorf("DualLogger: cloud logger did not receive log")
	}
	if err := serialLogs.checkLogContains(testMsg, payload{}); err != nil {
		t.Errorf("DualLogger: serial logger did not receive log: %v", err)
	}
}

func TestLogFunctions(t *testing.T) {
	testcases := []struct {
		name          string
		cloudSeverity clogging.Severity
		serialLevel   slog.Level
		logFunc       func(lgr Logger, msg string)
	}{
		{
			name:          "logger.Info",
			cloudSeverity: clogging.Info,
			serialLevel:   slog.LevelInfo,
			logFunc: func(lgr Logger, msg string) {
				lgr.Info(msg)
			},
		},
		{
			name:          "logger.Warn",
			cloudSeverity: clogging.Warning,
			serialLevel:   slog.LevelWarn,
			logFunc: func(lgr Logger, msg string) {
				lgr.Warn(msg)
			},
		},
		{
			name:          "logger.Error",
			cloudSeverity: clogging.Error,
			serialLevel:   slog.LevelError,
			logFunc: func(lgr Logger, msg string) {
				lgr.Error(msg)
			},
		},
	}

	msg := "test message"
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			cloudLogs := &testCLogger{}
			cl := &cloudLogger{
				cloudLogger:  cloudLogs,
				resource:     &mrpb.MonitoredResource{},
				instanceName: "test-instance",
			}

			serialLogs := &testSLogWriter{}
			sl := &serialLogger{
				slg: slog.New(slog.NewTextHandler(serialLogs, nil)),
			}

			mLogger := DualLogger(cl, sl)

			tc.logFunc(mLogger, msg)

			expectedPayload := payload{
				payloadMessageKey:      msg,
				payloadInstanceNameKey: cl.instanceName,
			}

			if cloudLogs.log.Severity != tc.cloudSeverity {
				t.Errorf("Cloud logs did not contain expected severity: got %v, want %v", cloudLogs.log.Severity, tc.cloudSeverity)
			}

			if !cmp.Equal(cloudLogs.log.Payload, expectedPayload) {
				t.Errorf("Cloud logs did not contain expected payload: got %v, want %v", cloudLogs.log.Payload, expectedPayload)
			}

			if err := serialLogs.checkLogContains(msg, payload{}); err != nil {
				t.Errorf("Error validating Serial Log contents: %v", err)
			}

			if err := serialLogs.checkLogLevel(tc.serialLevel); err != nil {
				t.Errorf("Error validating Serial Log level: %v", err)
			}
		})
	}
}

func TestSeverityWriter(t *testing.T) {
	tests := []struct {
		name         string
		writerFunc   func(Logger) io.Writer
		input        string
		wantMsg      string
		wantSeverity clogging.Severity
	}{
		{
			name:         "InfoWriter without newline",
			writerFunc:   NewInfoWriter,
			input:        "test info log",
			wantMsg:      "test info log",
			wantSeverity: clogging.Info,
		},
		{
			name:         "InfoWriter strips trailing newlines",
			writerFunc:   NewInfoWriter,
			input:        "test info log\n\n",
			wantMsg:      "test info log",
			wantSeverity: clogging.Info,
		},
		{
			name:         "ErrorWriter with trailing newline",
			writerFunc:   NewErrorWriter,
			input:        "test error log\n",
			wantMsg:      "test error log",
			wantSeverity: clogging.Error,
		},
		{
			name:         "Preserves internal newlines",
			writerFunc:   NewInfoWriter,
			input:        "line 1\nline 2\n\n",
			wantMsg:      "line 1\nline 2",
			wantSeverity: clogging.Info,
		},
		{
			name:         "Empty input",
			writerFunc:   NewInfoWriter,
			input:        "",
			wantMsg:      "",
			wantSeverity: clogging.Info,
		},
		{
			name:         "Only newlines",
			writerFunc:   NewInfoWriter,
			input:        "\n\n\n",
			wantMsg:      "",
			wantSeverity: clogging.Info,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mock := &mockLogger{}
			writer := tc.writerFunc(mock)
			n, err := writer.Write([]byte(tc.input))
			if err != nil || n != len(tc.input) {
				t.Fatalf("Write failed: got n=%v, err=%v", n, err)
			}
			if mock.severity != tc.wantSeverity {
				t.Errorf("Severity: got %v, want %v", mock.severity, tc.wantSeverity)
			}
			if mock.msg != tc.wantMsg {
				t.Errorf("Message: got %q, want %q", mock.msg, tc.wantMsg)
			}
		})
	}
}

type mockLogger struct {
	severity clogging.Severity
	msg      string
}

func (m *mockLogger) Log(severity clogging.Severity, msg string, _ ...any) {
	m.severity = severity
	m.msg = msg
}
func (m *mockLogger) Info(_ string, _ ...any)  {}
func (m *mockLogger) Warn(_ string, _ ...any)  {}
func (m *mockLogger) Error(_ string, _ ...any) {}
func (m *mockLogger) Close()                   {}
