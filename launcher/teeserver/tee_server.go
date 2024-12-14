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
	"path/filepath"

	"github.com/google/go-tpm-tools/launcher/agent"
	"github.com/google/go-tpm-tools/launcher/internal/logging"
	"github.com/google/go-tpm-tools/launcher/launcherfile"
)

type attestHandler struct {
	ctx              context.Context
	attestAgent      agent.AttestationAgent
	defaultTokenFile string
	logger           logging.Logger
}

type tokenOptions struct {
	Audience            string                  `json:"audience"`
	Nonce               []string                `json:"nonces"`
	TokenType           string                  `json:"token_type"`
	PrincipalTagOptions awsPrincipalTagsOptions `json:"aws_principal_tag_options"`
}

type containerImageSignatures struct {
	KeyIds []string `json:"key_ids"`
}

type allowedPrincipalTags struct {
	ContainerImageSignatures containerImageSignatures `json:"container_image_signatures"`
}

type awsPrincipalTagsOptions struct {
	AllowedPrincipalTags allowedPrincipalTags `json:"allowed_principal_tags"`
}

// TeeServer is a server that can be called from a container through a unix
// socket file.
type TeeServer struct {
	server      *http.Server
	netListener net.Listener
}

// New takes in a socket and start to listen to it, and create a server
func New(ctx context.Context, unixSock string, a agent.AttestationAgent, logger logging.Logger) (*TeeServer, error) {
	var err error
	nl, err := net.Listen("unix", unixSock)
	if err != nil {
		return nil, fmt.Errorf("cannot listen to the socket [%s]: %v", unixSock, err)
	}

	teeServer := TeeServer{
		netListener: nl,
		server: &http.Server{
			Handler: (&attestHandler{
				ctx:              ctx,
				attestAgent:      a,
				defaultTokenFile: filepath.Join(launcherfile.HostTmpPath, launcherfile.AttestationVerifierTokenFilename),
				logger:           logger,
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

	switch r.Method {
	case http.MethodGet:
		// this could call Attest(ctx) directly later.
		data, err := os.ReadFile(a.defaultTokenFile)

		if err != nil {
			err = fmt.Errorf("failed to get the token")
			a.logAndWriteHttpError(w, http.StatusNotFound, err)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write(data)
		return
	case http.MethodPost:
		var tokenOptions tokenOptions
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()

		err := decoder.Decode(&tokenOptions)
		if err != nil {
			a.logAndWriteHttpError(w, http.StatusBadRequest, err)
			return
		}

		err = validateTokenOptions(w, tokenOptions)
		if err != nil {
			a.logAndWriteHttpError(w, http.StatusBadRequest, err)
			return
		}

		tok, err := a.attestAgent.Attest(a.ctx,
			agent.AttestAgentOpts{
				Aud:       tokenOptions.Audience,
				Nonces:    tokenOptions.Nonce,
				TokenType: tokenOptions.TokenType,
			})
		if err != nil {
			a.logAndWriteHttpError(w, http.StatusBadRequest, err)
			return
		}

		w.WriteHeader(http.StatusOK)
		w.Write(tok)
		return
	default:
		// TODO: add an url pointing to the REST API document
		err := fmt.Errorf("TEE server recieved an invalid HTTP method: %s", r.Method)
		a.logAndWriteHttpError(w, http.StatusBadRequest, err)
	}
}

func (a *attestHandler) logAndWriteHttpError(w http.ResponseWriter, statusCode int, err error) {
	a.logger.Error(err.Error())
	w.WriteHeader(http.StatusBadRequest)
	w.Write([]byte(err.Error()))
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

func validateTokenOptions(w http.ResponseWriter, opts tokenOptions) error {
	if opts.Audience == "" {
		return fmt.Errorf("use GET request for the default identity token")
	}

	if opts.TokenType == "" {
		return fmt.Errorf("token_type is a required parameter")
	}

	//if opts.tokenType

	return nil
}
