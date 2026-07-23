// Package logging implements a logger to be used in the client.
// Logs to both Cloud Logging and the serial console.
package logging

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log/slog"
	"os"

	"cloud.google.com/go/compute/metadata"
	clogging "cloud.google.com/go/logging"
	"google.golang.org/api/option"
	mrpb "google.golang.org/genproto/googleapis/api/monitoredres"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

const (
	logName           = "confidential-space-launcher"
	serialConsoleFile = "/dev/console"

	payloadMessageKey      = "MESSAGE"
	payloadInstanceNameKey = "_HOSTNAME"
)

// Logger defines the interface for the CS image logger.
// Callers should run `defer logger.Close()` after initialization to ensure logs are flushed and handles are closed.
type Logger interface {
	Log(severity clogging.Severity, msg string, args ...any)

	Info(msg string, args ...any)
	Warn(msg string, args ...any)
	Error(msg string, args ...any)

	// Close flushes buffered logs and closes underlying resources. Callers should defer Close().
	Close()
}

type cLogger interface {
	Log(clogging.Entry)
	Flush() error
}

type cloudLogger struct {
	cloudLogger cLogger
	resource    *mrpb.MonitoredResource

	instanceName string
	cloudClient  *clogging.Client
}

type serialLogger struct {
	slg *slog.Logger
}

type dualLogger struct {
	cloud  Logger
	serial Logger
}

type payload map[string]any

// NewCloudLogger returns a Logger that logs exclusively to Cloud Logging.
// Callers should run `defer logger.Close()` after initialization to ensure logs are flushed and handles are closed.
func NewCloudLogger(ctx context.Context, pool *x509.CertPool) (Logger, error) {
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

	instanceName, err := mdsClient.InstanceNameWithContext(ctx)
	if err != nil {
		return nil, err
	}

	zone, err := mdsClient.ZoneWithContext(ctx)
	if err != nil {
		return nil, err
	}

	// Configure Cloud Logging client/logger.
	var opts []option.ClientOption
	if pool != nil {
		creds := credentials.NewTLS(&tls.Config{
			RootCAs: pool,
		})
		opts = append(opts, option.WithGRPCDialOption(grpc.WithTransportCredentials(creds)))
	}

	cloggingClient, err := clogging.NewClient(ctx, projectID, opts...)
	if err != nil {
		return nil, err
	}

	return &cloudLogger{
		cloudLogger: cloggingClient.Logger(logName),
		resource: &mrpb.MonitoredResource{
			Type: "gce_instance",
			Labels: map[string]string{
				"project_id":  projectID,
				"instance_id": instanceID,
				"zone":        zone,
			},
		},
		instanceName: instanceName,
		cloudClient:  cloggingClient,
	}, nil
}

// NewSerialLogger returns a Logger that logs exclusively to the provided serial console.
// It assumes serialConsole is a valid, writable file. The caller retains ownership of
// serialConsole and is responsible for closing it.
func NewSerialLogger(serialConsole *os.File) Logger {
	slg := slog.New(slog.NewTextHandler(serialConsole, nil))
	slg.Info("Serial Console logger initialized")

	// This is necessary for DEBUG logs to propagate properly.
	slog.SetDefault(slg)

	return &serialLogger{slg: slg}
}

// NullLogger returns a Logger that discards all logs.
func NullLogger() Logger {
	return &nullLogger{}
}

// DualLogger returns a Logger that duplicates its logs to both the cloud and serial loggers.
func DualLogger(cloud Logger, serial Logger) Logger {
	return &dualLogger{cloud: cloud, serial: serial}
}

func (l *cloudLogger) Log(severity clogging.Severity, msg string, args ...any) {
	if l.cloudLogger == nil {
		return
	}
	logEntry := clogging.Entry{
		Severity: severity,
		Resource: l.resource,
	}

	pl := payload{}
	addArgs(pl, args)

	if len(msg) > 0 {
		pl[payloadMessageKey] = msg
	}

	if len(l.instanceName) > 0 {
		// Needed for backwards compatibility with Cloudbuild tests.
		pl[payloadInstanceNameKey] = l.instanceName
	}

	logEntry.Payload = pl

	l.cloudLogger.Log(logEntry)
	if err := l.cloudLogger.Flush(); err != nil {
		slog.Error(fmt.Sprintf("cloud.Logger.Flush returned error: %v", err))
	}
}

func (l *cloudLogger) Info(msg string, args ...any)  { l.Log(clogging.Info, msg, args...) }
func (l *cloudLogger) Warn(msg string, args ...any)  { l.Log(clogging.Warning, msg, args...) }
func (l *cloudLogger) Error(msg string, args ...any) { l.Log(clogging.Error, msg, args...) }

func (l *cloudLogger) Close() {
	if l.cloudClient != nil {
		l.cloudClient.Close()
	}
}

// Given a list of args, recursively converts it to a payload.
// Assumes alternating keys and values (mirroring slog's behavior).
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

func (l *serialLogger) Log(severity clogging.Severity, msg string, args ...any) {
	switch severity {
	case clogging.Info, clogging.Notice, clogging.Debug:
		l.slg.Info(msg, args...)
	case clogging.Warning:
		l.slg.Warn(msg, args...)
	case clogging.Error, clogging.Critical, clogging.Alert, clogging.Emergency:
		l.slg.Error(msg, args...)
	default:
		slog.Debug(msg, args...)
	}
}

func (l *serialLogger) Info(msg string, args ...any)  { l.Log(clogging.Info, msg, args...) }
func (l *serialLogger) Warn(msg string, args ...any)  { l.Log(clogging.Warning, msg, args...) }
func (l *serialLogger) Error(msg string, args ...any) { l.Log(clogging.Error, msg, args...) }

func (l *serialLogger) Close() {}

func (d *dualLogger) Log(severity clogging.Severity, msg string, args ...any) {
	d.cloud.Log(severity, msg, args...)
	d.serial.Log(severity, msg, args...)
}

func (d *dualLogger) Info(msg string, args ...any) {
	d.cloud.Info(msg, args...)
	d.serial.Info(msg, args...)
}

func (d *dualLogger) Warn(msg string, args ...any) {
	d.cloud.Warn(msg, args...)
	d.serial.Warn(msg, args...)
}

func (d *dualLogger) Error(msg string, args ...any) {
	d.cloud.Error(msg, args...)
	d.serial.Error(msg, args...)
}

func (d *dualLogger) Close() {
	d.cloud.Close()
	d.serial.Close()
}

// SimpleLogger returns a lightweight implementation that wraps a slog.Default() logger.
// Suitable for testing.
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

func (l *slogger) Close() {}

type nullLogger struct{}

func (n *nullLogger) Log(_ clogging.Severity, _ string, _ ...any) {}
func (n *nullLogger) Info(_ string, _ ...any)                     {}
func (n *nullLogger) Warn(_ string, _ ...any)                     {}
func (n *nullLogger) Error(_ string, _ ...any)                    {}
func (n *nullLogger) Close()                                      {}

// SeverityWriter wraps a Logger and implements io.Writer to write to the Logger at a specific severity level.
type SeverityWriter struct {
	l        Logger
	severity clogging.Severity
}

// NewSeverityWriter returns an io.Writer that writes to the provided Logger with a specific severity.
func NewSeverityWriter(l Logger, severity clogging.Severity) io.Writer {
	return &SeverityWriter{l: l, severity: severity}
}

// NewInfoWriter returns an io.Writer that writes logs to the provided Logger with Info severity.
func NewInfoWriter(l Logger) io.Writer {
	return NewSeverityWriter(l, clogging.Info)
}

// NewErrorWriter returns an io.Writer that writes logs to the provided Logger with Error severity.
func NewErrorWriter(l Logger) io.Writer {
	return NewSeverityWriter(l, clogging.Error)
}

// Write implements the io.Writer interface, redirecting logs to the Logger with the configured severity.
func (w *SeverityWriter) Write(p []byte) (n int, err error) {
	// Trim any trailing newline.
	end := len(p)
	for end > 0 && p[end-1] == '\n' {
		end--
	}
	msg := string(p[:end])

	w.l.Log(w.severity, msg)

	return len(p), nil
}
