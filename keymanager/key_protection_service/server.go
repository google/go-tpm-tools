package keyprotectionservice

import (
	"context"
	"fmt"
	"net"

	"google.golang.org/grpc"
)

// Server is the Key Protection Service gRPC server.
type Server struct {
	grpcServer *grpc.Server
	listener   net.Listener
	kps        KeyProtectionService
}

// NewServer creates a new KPS gRPC server listening on the given TCP port.
func NewServer(port int) (*Server, error) {
	return newServerWithKPS(port, NewService())
}

// newServerWithKPS creates a new KPS gRPC server with the given dependencies.
func newServerWithKPS(port int, kps KeyProtectionService) (*Server, error) {
	addr := fmt.Sprintf(":%d", port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("failed to listen on TCP port %d: %w", port, err)
	}

	grpcServer := grpc.NewServer()

	// TODO: Add the KPS gRPC API endpoints here.

	return &Server{
		grpcServer: grpcServer,
		listener:   ln,
		kps:        kps,
	}, nil
}

// Serve starts the gRPC server listening on the given port.
func (s *Server) Serve() error {
	return s.grpcServer.Serve(s.listener)
}

// Shutdown gracefully shuts down the server.
func (s *Server) Shutdown(ctx context.Context) error {
	shutdownDone := make(chan struct{})
	go func() {
		s.grpcServer.GracefulStop()
		close(shutdownDone)
	}()

	select {
	case <-ctx.Done():
		s.grpcServer.Stop() // Force stop if context is cancelled
		return ctx.Err()
	case <-shutdownDone:
		return nil
	}
}
