// Package teeserver implements a server to be run in the launcher.
// Used for communicate between the host/launcher and the container.
package teeserver

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"

	"github.com/google/go-tpm-tools/launcher/agent"
	"github.com/google/go-tpm-tools/launcher/launcherfile"
)

type attestHandler struct {
	attestAgent agent.AttestationAgent
	logger      *log.Logger
}

// TeeServer is a server that can be called from a container through a unix
// socket file.
type TeeServer struct {
	server      *http.Server
	netListener net.Listener
}

// New takes in a socket and start to listen to it, and create a server
func New(unixSock string, a agent.AttestationAgent, logger *log.Logger) (*TeeServer, error) {
	var err error
	nl, err := net.Listen("unix", unixSock)
	if err != nil {
		return nil, fmt.Errorf("cannot listen to the socket [%s]: %v", unixSock, err)
	}

	teeServer := TeeServer{
		netListener: nl,
		server: &http.Server{
			Handler: (&attestHandler{attestAgent: a, logger: logger}).Handler(),
		},
	}
	return &teeServer, nil
}

// Handler creates a multiplexer for the server.
func (a *attestHandler) Handler() http.Handler {
	mux := http.NewServeMux()
	// curl --unix-socket <socket> http:/unix/v1/defaultToken
	mux.HandleFunc("/v1/defaultToken", a.getDefaultToken)
	return mux
}

// getDefaultToken handles the request to get the default OIDC token.
// For now this function will just read the content of the file and return.
// Later, this function can use attestation agent to get a token directly.
func (a *attestHandler) getDefaultToken(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html")

	// this could be calling Attest(context.Background()) directly later.
	data, err := os.ReadFile(filepath.Join(launcherfile.HostTmpPath, launcherfile.AttestationVerifierTokenFilename))
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("failed to get the token"))
	} else {
		w.WriteHeader(http.StatusOK)
		w.Write(data)
	}
}

// Serve starts the server, will block until the server shutdown.
func (s *TeeServer) Serve() error {
	return s.server.Serve(s.netListener)
}

// Shutdown will terminate the server and the underlying listener.
func (s *TeeServer) Shutdown(ctx context.Context) error {
	err := s.server.Shutdown(ctx)
	err2 := s.netListener.Close()

	if err != nil {
		return err
	}
	if err2 != nil {
		return err2
	}
	return nil
}
