package cmd

import (
	"context"
	"fmt"
	"log"
	"net"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	logpb "cloud.google.com/go/logging/apiv2/loggingpb"
	tspb "github.com/golang/protobuf/ptypes/timestamp"
	"github.com/google/go-tpm-tools/internal/util"
	"google.golang.org/grpc"
)

// The only IDs that WriteLogEntries will accept.
const (
	TestProjectID = "test-project"
)

// A fakeServer is an in-process gRPC server, listening on a system-chosen port on
// the local loopback interface. Servers are for testing only and are not
// intended to be used in production code.
type fakeServer struct {
	Addr string
	Port int
	l    net.Listener
	Gsrv *grpc.Server
}

// Start causes the server to start accepting incoming connections.
// Call Start after registering handlers.
func (s *fakeServer) Start() {
	go func() {
		if err := s.Gsrv.Serve(s.l); err != nil {
			log.Printf("fake_cloudlogging_server.fakeServer.Start: %v", err)
		}
	}()
}

// Close shuts down the server.
func (s *fakeServer) Close() {
	s.Gsrv.Stop()
	s.l.Close()
}

// newFakeServer creates a new Server. The Server will be listening for gRPC connections
// at the address named by the Addr field, without TLS.
func newFakeServer(opts ...grpc.ServerOption) (*fakeServer, error) {
	return newFakeServerWithPort(0, opts...)
}

// newFakeServerWithPort creates a new Server at a specific port. The Server will be listening
// for gRPC connections at the address named by the Addr field, without TLS.
func newFakeServerWithPort(port int, opts ...grpc.ServerOption) (*fakeServer, error) {
	l, err := net.Listen("tcp", fmt.Sprintf("localhost:%d", port))
	if err != nil {
		return nil, err
	}
	s := &fakeServer{
		Addr: l.Addr().String(),
		Port: parsePort(l.Addr().String()),
		l:    l,
		Gsrv: grpc.NewServer(opts...),
	}
	return s, nil
}

var portParser = regexp.MustCompile(`:[0-9]+`)

func parsePort(addr string) int {
	res := portParser.FindAllString(addr, -1)
	if len(res) == 0 {
		panic(fmt.Errorf("parsePort: found no numbers in %s", addr))
	}
	stringPort := res[0][1:] // strip the :
	p, err := strconv.ParseInt(stringPort, 10, 32)
	if err != nil {
		panic(err)
	}
	return int(p)
}

type loggingHandler struct {
	logpb.LoggingServiceV2Server

	mu   sync.Mutex
	logs map[string][]*logpb.LogEntry // indexed by log name
}

// WriteLogEntries writes log entries to Cloud Logging. All log entries in
// Cloud Logging are written by this method.
func (h *loggingHandler) WriteLogEntries(_ context.Context, req *logpb.WriteLogEntriesRequest) (*logpb.WriteLogEntriesResponse, error) {
	if !strings.HasPrefix(req.LogName, "projects/"+TestProjectID+"/") {
		return nil, fmt.Errorf("bad LogName: %q", req.LogName)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, e := range req.Entries {
		// Assign timestamp if missing.
		if e.Timestamp == nil {
			e.Timestamp = &tspb.Timestamp{Seconds: time.Now().Unix(), Nanos: 0}
		}
		// Fill from common fields in request.
		if e.LogName == "" {
			e.LogName = req.LogName
		}
		if e.Resource == nil {
			e.Resource = req.Resource
		}
		for k, v := range req.Labels {
			if _, ok := e.Labels[k]; !ok {
				e.Labels[k] = v
			}
		}

		// Store by log name.
		h.logs[e.LogName] = append(h.logs[e.LogName], e)
	}

	var logEntryPayload []map[string]interface{}
	logEntryPayload = append(logEntryPayload, map[string]interface{}{"aud": "test", "iat": float64(1709752525), "exp": float64(1919752525)})
	logEntryPayload = append(logEntryPayload, map[string]interface{}{"token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJ0ZXN0IiwiaWF0IjoxNzA5NzUyNTI1LCJleHAiOjE5MTk3NTI1MjV9.EBLA2zX3c-Fu0l--J9Gey6LIXMO1TFRCoe3bzuPGc1k"})
	logEntryPayload = append(logEntryPayload, map[string]interface{}{"Name": "projects/test-project/locations/us-central-1/challenges/" + util.FakeChallengeUUID, "Nonce": util.FakeTpmNonce, "ConnID": ""})
	attestationMapFields := []string{"TeeAttestation", "ak_pub", "quotes", "event_log", "ak_cert"}
	for _, entry := range h.logs["projects/"+TestProjectID+"/logs/"+toolName] {
		payload := entry.GetJsonPayload().AsMap()
		foundMatch := false
		for _, m := range logEntryPayload {
			if reflect.DeepEqual(m, payload) {
				foundMatch = true
			}
		}
		if !foundMatch {
			for _, field := range attestationMapFields {
				if _, keyFound := payload[field]; !keyFound {
					return nil, fmt.Errorf("wrong log: %q", entry.GetJsonPayload().String())
				}
			}
		}
	}
	return &logpb.WriteLogEntriesResponse{}, nil
}

// newMockCloudLoggingServer creates a new in-memory fake server implementing the logging service.
// It returns the address of the server.
func newMockCloudLoggingServer() (string, error) {
	srv, err := newFakeServer()
	if err != nil {
		return "", err
	}
	logpb.RegisterLoggingServiceV2Server(srv.Gsrv, &loggingHandler{
		logs: make(map[string][]*logpb.LogEntry),
	})

	srv.Start()
	return srv.Addr, nil
}
