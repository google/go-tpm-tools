// Package teeserver implements a server to be run in the launcher.
// Used for communicate between the host/launcher and the container.
package teeserver

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"

	"github.com/google/go-tpm-tools/launcher/agent"
	"github.com/google/go-tpm-tools/launcher/internal/logging"
	"github.com/google/go-tpm-tools/launcher/spec"
	"github.com/google/go-tpm-tools/verifier"
	"github.com/google/go-tpm-tools/verifier/models"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	gcaEndpoint = "/v1/token"
	itaEndpoint = "/v1/intel/token"

	verifyMethodHeader = "Verify-Method"
)

var clientErrorCodes = map[codes.Code]struct{}{
	codes.InvalidArgument:    {},
	codes.FailedPrecondition: {},
	codes.PermissionDenied:   {},
	codes.Unauthenticated:    {},
	codes.NotFound:           {},
	codes.Aborted:            {},
	codes.OutOfRange:         {},
	codes.Canceled:           {},
}

// AttestClients contains clients for supported verifier services that can be used to
// get attestation tokens.
type AttestClients struct {
	GCA verifier.Client
	ITA verifier.Client
}

type attestHandler struct {
	ctx         context.Context
	attestAgent agent.AttestationAgent
	// defaultTokenFile string
	logger     logging.Logger
	launchSpec spec.LaunchSpec
	clients    AttestClients
}

// TeeServer is a server that can be called from a container through a unix
// socket file.
type TeeServer struct {
	server      *http.Server
	netListener net.Listener
}

// New takes in a socket and start to listen to it, and create a server
func New(ctx context.Context, unixSock string, a agent.AttestationAgent, logger logging.Logger, launchSpec spec.LaunchSpec, clients AttestClients) (*TeeServer, error) {
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
				logger:      logger,
				launchSpec:  launchSpec,
				clients:     clients,
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

	mux.HandleFunc(gcaEndpoint, a.getToken)
	mux.HandleFunc(itaEndpoint, a.getITAToken)
	return mux
}

func (a *attestHandler) logAndWriteError(errStr string, status int, w http.ResponseWriter) {
	a.logger.Error(errStr)
	w.WriteHeader(status)
	w.Write([]byte(errStr))
}

// getDefaultToken handles the request to get the default OIDC token.
// For now this function will just read the content of the file and return.
// Later, this function can use attestation agent to get a token directly.
func (a *attestHandler) getToken(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")

	a.logger.Info(fmt.Sprintf("%s called", gcaEndpoint))

	// If the handler does not have an GCA client, return error.
	if a.clients.GCA == nil {
		errStr := "no GCA verifier client present, please try rebooting your VM"
		a.logAndWriteError(errStr, http.StatusInternalServerError, w)
		return
	}

	a.attest(w, r, a.clients.GCA)
}

// getITAToken retrieves a attestation token signed by ITA.
func (a *attestHandler) getITAToken(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")

	a.logger.Info(fmt.Sprintf("%s called", itaEndpoint))

	// If the handler does not have an ITA client, return error.
	if a.clients.ITA == nil {
		errStr := "no ITA verifier client present - ensure ITA Region and Key are defined in metadata"
		a.logAndWriteError(errStr, http.StatusInternalServerError, w)
		return
	}

	a.attest(w, r, a.clients.ITA)
}

func parseVerifyMethod(headers http.Header) agent.VerifyMethod {
	if headers == nil {
		return agent.VerifyUnset
	}

	methods, ok := headers[verifyMethodHeader]
	if !ok {
		return agent.VerifyUnset
	}

	// Expect only one method specified.
	if len(methods) != 1 {
		return agent.VerifyUnset
	}

	switch methods[0] {
	case string(agent.VerifyConfidentialSpaceMethod):
		return agent.VerifyConfidentialSpaceMethod
	case string(agent.VerifyAttestationMethod):
		return agent.VerifyAttestationMethod
	default:
		return agent.VerifyUnset
	}
}

func (a *attestHandler) attest(w http.ResponseWriter, r *http.Request, client verifier.Client) {
	verifyMethod := parseVerifyMethod(r.Header)
	logStr := fmt.Sprintf("Parsed VerifyMethod: %v", verifyMethod)
	a.logger.Info(logStr)

	switch r.Method {
	case http.MethodGet:
		if err := a.attestAgent.Refresh(a.ctx); err != nil {
			a.logAndWriteHTTPError(w, http.StatusInternalServerError, fmt.Errorf("failed to refresh attestation agent: %w", err))
			return
		}

		token, err := a.attestAgent.AttestWithClient(a.ctx, agent.AttestAgentOpts{
			Method: verifyMethod,
		}, client)
		if err != nil {
			a.handleAttestError(w, err, "failed to retrieve attestation service token")
			return
		}

		w.WriteHeader(http.StatusOK)
		w.Write(token)
		return

	case http.MethodPost:
		var tokenOptions models.TokenOptions
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()

		err := decoder.Decode(&tokenOptions)
		if err != nil {
			err = fmt.Errorf("failed to parse POST body as TokenOptions: %v", err)
			a.logAndWriteHTTPError(w, http.StatusBadRequest, err)
			return
		}

		if tokenOptions.Audience == "" {
			err := fmt.Errorf("use GET request for the default identity token")
			a.logAndWriteHTTPError(w, http.StatusBadRequest, err)
			return
		}

		if tokenOptions.TokenType == "" {
			err := fmt.Errorf("token_type is a required parameter")
			a.logAndWriteHTTPError(w, http.StatusBadRequest, err)
			return
		}

		// Do not check that TokenTypeOptions matches TokenType in the launcher.
		opts := agent.AttestAgentOpts{
			TokenOptions: &tokenOptions,
			Method:       verifyMethod,
		}
		tok, err := a.attestAgent.AttestWithClient(a.ctx, opts, client)
		if err != nil {
			a.handleAttestError(w, err, "failed to retrieve custom attestation service token")
			return
		}

		w.WriteHeader(http.StatusOK)
		w.Write(tok)
		return
	default:
		// TODO: add an url pointing to the REST API document
		err := fmt.Errorf("TEE server received an invalid HTTP method: %s", r.Method)
		a.logAndWriteHTTPError(w, http.StatusBadRequest, err)
	}
}

func (a *attestHandler) logAndWriteHTTPError(w http.ResponseWriter, statusCode int, err error) {
	a.logger.Error(err.Error())
	w.WriteHeader(statusCode)
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

func (a *attestHandler) handleAttestError(w http.ResponseWriter, err error, message string) {
	st, ok := status.FromError(err)
	if ok {
		if _, exists := clientErrorCodes[st.Code()]; exists {
			// User errors, like invalid arguments. Map user errors to 400 Bad Request.
			a.logAndWriteHTTPError(w, http.StatusBadRequest, fmt.Errorf("%s: %w", message, err))
			return
		}
		// Server-side or transient errors. Map user errors 500 Internal Server Error.
		a.logAndWriteHTTPError(w, http.StatusInternalServerError, fmt.Errorf("%s: %w", message, err))
		return
	}
	// If it's not a gRPC error, it's likely an internal error within the launcher.
	// Map user errors 500 Internal Server Error
	a.logAndWriteHTTPError(w, http.StatusInternalServerError, fmt.Errorf("%s: %w", message, err))
}
