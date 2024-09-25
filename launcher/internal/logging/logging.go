// Package logging implements a logger to be used in the client.
// Logs to both Cloud Logging and the serial console.
package logging

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"cloud.google.com/go/compute/metadata"
	clogging "cloud.google.com/go/logging"
	mrpb "google.golang.org/genproto/googleapis/api/monitoredres"
)

const (
	logName           = "projects/confidentialcomputing-e2e/logs/confidential-space-launcher"
	serialConsoleFile = "/dev/console"
)

// Logger defines the interface for the CS image logger.
type Logger interface {
	Log(severity clogging.Severity, msg string, args ...any)

	Info(msg string, args ...any)
	Warn(msg string, args ...any)
	Error(msg string, args ...any)
	Debug(msg string, args ...any)

	SerialConsoleFile() *os.File
	Close()
}

type logger struct {
	cloudLogger  *clogging.Logger
	serialLogger *slog.Logger
	resource     *mrpb.MonitoredResource

	cloudClient       *clogging.Client
	serialConsoleFile *os.File
}

type payload map[string]any

// NewLogger returns a Logger with Cloud and Serial Console logging configured.
func NewLogger(ctx context.Context) (Logger, error) {
	// Retrieve monitored resource information.
	mdsClient := metadata.NewClient(nil)

	projectID, err := mdsClient.ProjectIDWithContext(ctx)
	if err != nil {
		return nil, err
	}

	instanceID, err := mdsClient.InstanceIDWithContext(ctx)
	if err != nil {
		return nil, err
	}

	zone, err := mdsClient.ZoneWithContext(ctx)
	if err != nil {
		return nil, err
	}

	// Configure Cloud Logging client/logger.
	cloggingClient, err := clogging.NewClient(ctx, projectID)
	if err != nil {
		return nil, err
	}

	// Configure Serial Console logger.
	serialConsole, err := os.OpenFile(serialConsoleFile, os.O_WRONLY, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to open serial console for writing: %v", err)
	}

	slg := slog.New(slog.NewJSONHandler(serialConsole, nil))
	slg.Info("Serial Console logger initialized")

	return &logger{
		cloudLogger:  cloggingClient.Logger(logName),
		serialLogger: slg,
		resource: &mrpb.MonitoredResource{
			Type: "gce_instance",
			Labels: map[string]string{
				"project_id":  projectID,
				"instance_id": instanceID,
				"zone":        zone,
			},
		},
		cloudClient:       cloggingClient,
		serialConsoleFile: serialConsole,
	}, err
}

func (l *logger) SerialConsoleFile() *os.File {
	return l.serialConsoleFile
}

func (l *logger) Close() {
	if l.cloudClient != nil {
		l.cloudClient.Close()
	}

	if l.serialConsoleFile != nil {
		l.serialConsoleFile.Close()
	}
}

func addArgs(pl payload, args []any) {
	// Base case - if args is empty.
	if len(args) == 0 {
		return
	}

	// Base case - if args has one element.
	if len(args) == 1 {
		// If the arg is a valid key, add with empty value.
		key, ok := args[0].(string)
		if ok {
			pl[key] = ""
		}
		return
	}

	key, ok := args[0].(string)
	if ok {
		// If key is a valid string, add pair to payload. Otherwise, the pair is skipped.
		pl[key] = args[1]
	}

	// Recurse with remaining args.
	addArgs(pl, args[2:])
}

func (l *logger) writeLog(severity clogging.Severity, msg string, args ...any) {
	// Write cloud log.
	logEntry := clogging.Entry{
		Severity: severity,
		Resource: l.resource,
	}

	pl := payload{}
	addArgs(pl, args)

	pl["message"] = msg
	logEntry.Payload = pl

	l.cloudLogger.Log(logEntry)
	l.cloudLogger.Flush()

	// Write to serial console.
	switch severity {
	case clogging.Info, clogging.Notice:
		l.serialLogger.Info(msg, args...)
	case clogging.Warning:
		l.serialLogger.Warn(msg, args...)
	case clogging.Error, clogging.Critical, clogging.Alert, clogging.Emergency:
		l.serialLogger.Error(msg, args...)
	default:
		l.serialLogger.Debug(msg, args...)
	}
}

// Log logs msg and args with the provided severity.
func (l *logger) Log(severity clogging.Severity, msg string, args ...any) {
	l.writeLog(severity, msg, args...)
}

// Info logs msg and args at 'Info' severity.
func (l *logger) Info(msg string, args ...any) {
	l.writeLog(clogging.Info, msg, args...)
}

// Warn logs msg and args at 'Warn' severity.
func (l *logger) Warn(msg string, args ...any) {
	l.writeLog(clogging.Warning, msg, args...)
}

// Error logs msg and args at 'Error' severity.
func (l *logger) Error(msg string, args ...any) {
	l.writeLog(clogging.Error, msg, args...)
}

// Debug logs msg and args at 'Debug' severity.
func (l *logger) Debug(msg string, args ...any) {
	l.writeLog(clogging.Debug, msg, args...)
}

// SimpleLogger returns a lightweight implementation that wraps a slog.Default() logger.
func SimpleLogger() Logger {
	return &slogger{slog.Default()}
}

type slogger struct {
	slg *slog.Logger
}

// Log logs msg and args with the provided severity.
func (l *slogger) Log(severity clogging.Severity, msg string, args ...any) {
	level := slog.LevelDebug
	switch severity {
	case clogging.Info, clogging.Notice:
		level = slog.LevelInfo
	case clogging.Warning:
		level = slog.LevelWarn
	case clogging.Error, clogging.Critical, clogging.Alert, clogging.Emergency:
		level = slog.LevelError
	}
	l.slg.Log(context.Background(), level, msg, args...)
}

// Info logs msg and args at 'Info' severity.
func (l *slogger) Info(msg string, args ...any) {
	l.slg.Info(msg, args...)
}

// Warn logs msg and args at 'Warn' severity.
func (l *slogger) Warn(msg string, args ...any) {
	l.slg.Warn(msg, args...)
}

// Error logs msg and args at 'Error' severity.
func (l *slogger) Error(msg string, args ...any) {
	l.slg.Error(msg, args...)
}

// Debug logs msg and args at 'Debug' severity.
func (l *slogger) Debug(msg string, args ...any) {
	l.slg.Debug(msg, args...)
}

func (l *slogger) SerialConsoleFile() *os.File {
	return nil
}

func (l *slogger) Close() {}
