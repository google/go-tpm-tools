// Package teeserver implements a server to be run in the launcher.
// Used for communicate between the host/launcher and the container.
package teeserver

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"

	"github.com/google/go-tpm-tools/launcher/agent"
	"github.com/google/go-tpm-tools/launcher/internal/logging"
	"github.com/google/go-tpm-tools/launcher/spec"
	"github.com/google/go-tpm-tools/verifier/util"
)

type attestHandler struct {
	ctx         context.Context
	attestAgent agent.AttestationAgent
	// defaultTokenFile string
	logger     logging.Logger
	launchSpec spec.LaunchSpec
}

type customTokenRequest struct {
	Audience  string   `json:"audience"`
	Nonces    []string `json:"nonces"`
	TokenType string   `json:"token_type"`
}

// TeeServer is a server that can be called from a container through a unix
// socket file.
type TeeServer struct {
	server      *http.Server
	netListener net.Listener
}

// New takes in a socket and start to listen to it, and create a server
func New(ctx context.Context, unixSock string, a agent.AttestationAgent, logger logging.Logger, launchSpec spec.LaunchSpec) (*TeeServer, error) {
	var err error
	nl, err := net.Listen("unix", unixSock)
	if err != nil {
		return nil, fmt.Errorf("cannot listen to the socket [%s]: %v", unixSock, err)
	}

	teeServer := TeeServer{
		netListener: nl,
		server: &http.Server{
			Handler: (&attestHandler{
				ctx:         ctx,
				attestAgent: a,
				// defaultTokenFile: filepath.Join(launcherfile.HostTmpPath, launcherfile.AttestationVerifierTokenFilename),
				logger:     logger,
				launchSpec: launchSpec,
			}).Handler(),
		},
	}
	return &teeServer, nil
}

// Handler creates a multiplexer for the server.
func (a *attestHandler) Handler() http.Handler {
	mux := http.NewServeMux()
	// to test default token: curl --unix-socket <socket> http://localhost/v1/token
	// to test custom token:
	// curl -d '{"audience":"<aud>", "nonces":["<nonce1>"]}' -H "Content-Type: application/json" -X POST
	//   --unix-socket /tmp/container_launcher/teeserver.sock http://localhost/v1/token

	mux.HandleFunc("/v1/token", a.getToken)
	return mux
}

// getDefaultToken handles the request to get the default OIDC token.
// For now this function will just read the content of the file and return.
// Later, this function can use attestation agent to get a token directly.
func (a *attestHandler) getToken(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")

	// If the agent does not have a GCA client, create one.
	if !a.attestAgent.HasClient(agent.GCA) {
		gcaClient, err := util.NewRESTClient(a.ctx, a.launchSpec.AttestationServiceAddr, a.launchSpec.ProjectID, a.launchSpec.Region)
		if err != nil {
			errStr := fmt.Sprintf("failed to create REST verifier client: %v", err)
			a.logger.Error(errStr)
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(errStr))
			return
		}

		a.attestAgent.AddClient(gcaClient, agent.GCA)
	}

	switch r.Method {
	case "GET":
		// this could call Attest(ctx) directly later.
		data, err := os.ReadFile(a.defaultTokenFile)

		if err != nil {
			a.logger.Error(err.Error())
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte("failed to get the token"))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write(data)
		return
	case "POST":
		var tokenReq customTokenRequest
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()

		err := decoder.Decode(&tokenReq)
		if err != nil {
			a.logger.Error(err.Error())
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(err.Error()))
			return
		}

		if tokenReq.Audience == "" {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("use GET request for the default identity token"))
			return
		}

		if tokenReq.TokenType == "" {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("token_type is a required parameter"))
			return
		}

		tok, err := a.attestAgent.Attest(a.ctx,
			agent.AttestAgentOpts{
				Aud:       tokenReq.Audience,
				Nonces:    tokenReq.Nonces,
				TokenType: tokenReq.TokenType,
			})
		if err != nil {
			a.logger.Error(err.Error())
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(err.Error()))
			return
		}

		w.WriteHeader(http.StatusOK)
		w.Write(tok)
		return
	}

	w.WriteHeader(http.StatusBadRequest)
	// TODO: add an url pointing to the REST API document
	w.Write([]byte("TEE server received invalid request"))
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
