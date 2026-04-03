// Package teeserver implements a server to be run in the launcher.
// Used for communicate between the host/launcher and the container.
package teeserver

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"

	attestationpb "github.com/GoogleCloudPlatform/confidential-space/server/proto/gen/attestation"
	"github.com/google/go-tpm-tools/agent"
	keymanager "github.com/google/go-tpm-tools/keymanager/km_common/proto"
	wsd "github.com/google/go-tpm-tools/keymanager/workload_service"
	"github.com/google/go-tpm-tools/launcher/internal/logging"
	"github.com/google/go-tpm-tools/launcher/spec"
	tspb "github.com/google/go-tpm-tools/launcher/teeserver/proto/gen/teeserver"
	"github.com/google/go-tpm-tools/verifier"
	"github.com/google/go-tpm-tools/verifier/models"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

const (
	gcaEndpoint             = "/v1/token"
	itaEndpoint             = "/v1/intel/token"
	evidenceEndpoint        = "/v1/evidence"
	endorsementEndpoint     = "/v1/keys:getEndorsement"
	hostAttestationEndpoint = "/v1/hostAttestation"
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
	logger            logging.Logger
	launchSpec        spec.LaunchSpec
	clients           AttestClients
	keyClaimsProvider wsd.KeyClaimsProvider
}

// TeeServer is a server that can be called from a container through a unix
// socket file.
type TeeServer struct {
	server      *http.Server
	netListener net.Listener
}

// New takes in a socket and start to listen to it, and create a server
func New(ctx context.Context, unixSock string, a agent.AttestationAgent, logger logging.Logger, launchSpec spec.LaunchSpec, clients AttestClients, keyClaimsProvider wsd.KeyClaimsProvider) (*TeeServer, error) {
	var err error
	nl, err := net.Listen("unix", unixSock)
	if err != nil {
		return nil, fmt.Errorf("cannot listen to the socket [%s]: %v", unixSock, err)
	}

	if launchSpec.Experiments.EnableKeyManager && keyClaimsProvider == nil {
		return nil, fmt.Errorf("key claims provider cannot be nil when key manager is enabled")
	}

	teeServer := TeeServer{
		netListener: nl,
		server: &http.Server{
			Handler: (&attestHandler{
				ctx:               ctx,
				attestAgent:       a,
				logger:            logger,
				launchSpec:        launchSpec,
				clients:           clients,
				keyClaimsProvider: keyClaimsProvider,
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
	// to test attestation evidence:
	// curl -d '{"challenge":"<challenge>"}' -H "Content-Type: application/json" -X POST
	//   --unix-socket /tmp/container_launcher/teeserver.sock http://localhost/v1/evidence

	mux.HandleFunc(gcaEndpoint, a.getToken)
	mux.HandleFunc(itaEndpoint, a.getITAToken)
	mux.HandleFunc(evidenceEndpoint, a.getAttestationEvidence)
	mux.HandleFunc(endorsementEndpoint, a.getKeyEndorsement)
	mux.HandleFunc(hostAttestationEndpoint, a.getHostAttestation)
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

// getAttestationEvidence retrieves the attestation evidence.
// It returns partial response with query parameter support.
// It currently supports "label", "challenge", "quote", "extraData", and "deviceReports" params.
// The default response with no query parameter will return all fields except device reports.
// If the fields param is "*", it will return all fields including device reports.
func (a *attestHandler) getAttestationEvidence(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		a.logAndWriteHTTPError(w, http.StatusMethodNotAllowed, fmt.Errorf("method not allowed"))
		return
	}

	a.logger.Info(fmt.Sprintf("%s called", evidenceEndpoint))

	var req tspb.GetAttestationEvidenceRequest
	body, err := io.ReadAll(r.Body)
	if err != nil {
		a.logAndWriteHTTPError(w, http.StatusBadRequest, fmt.Errorf("failed to read request body: %v", err))
		return
	}
	if err := protojson.Unmarshal(body, &req); err != nil {
		a.logAndWriteHTTPError(w, http.StatusBadRequest, fmt.Errorf("failed to decode request: %v", err))
		return
	}
	if len(req.Challenge) == 0 {
		a.logAndWriteHTTPError(w, http.StatusBadRequest, fmt.Errorf("challenge is required"))
		return
	}

	fields := r.URL.Query().Get("fields")
	attestOpts := agent.AttestAgentOpts{
		DeviceReportOpts: &agent.DeviceReportOpts{
			EnableRuntimeGPUAttestation: fields == "*" || strings.Contains(fields, "deviceReports"),
		},
	}
	evidence, err := a.attestAgent.AttestationEvidence(a.ctx, req.Challenge, nil, attestOpts)
	if err != nil {
		a.logAndWriteHTTPError(w, http.StatusInternalServerError, err)
		return
	}

	partialEvidence, err := filterVMAttestationFields(evidence, fields)
	if err != nil {
		a.logAndWriteHTTPError(w, http.StatusBadRequest, fmt.Errorf("invalid fields parameter: %v", err))
		return
	}

	evidenceBytes, err := protojson.Marshal(partialEvidence)
	if err != nil {
		a.logAndWriteHTTPError(w, http.StatusInternalServerError, fmt.Errorf("failed to marshal evidence: %v", err))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(evidenceBytes)
}

// filterVMAttestationFields return a partial VM Attestation based on the query parameters.
func filterVMAttestationFields(att *attestationpb.VmAttestation, fields string) (*attestationpb.VmAttestation, error) {
	if fields == "" || fields == "*" {
		return att, nil
	}
	fieldSlice := strings.Split(fields, ",")
	fieldMap := make(map[string]bool)
	for _, f := range fieldSlice {
		fieldMap[strings.TrimSpace(f)] = true
	}

	out := &attestationpb.VmAttestation{}
	if fieldMap["label"] {
		out.Label = att.GetLabel()
	}
	if fieldMap["challenge"] {
		out.Challenge = att.GetChallenge()
	}
	if fieldMap["extraData"] {
		out.ExtraData = att.GetExtraData()
	}
	if fieldMap["quote"] {
		out.Quote = att.GetQuote()
	}
	if fieldMap["deviceReports"] {
		out.DeviceReports = att.GetDeviceReports()
	}
	return out, nil
}

// getKeyEndorsement retrieves the attestation evidence with KEM and binding key claims.
func (a *attestHandler) getKeyEndorsement(w http.ResponseWriter, r *http.Request) {
	if !a.launchSpec.Experiments.EnableKeyManager {
		a.logAndWriteHTTPError(w, http.StatusForbidden, fmt.Errorf("keymanager not enabled"))
		return
	}

	if r.Method != http.MethodPost {
		a.logAndWriteHTTPError(w, http.StatusMethodNotAllowed, fmt.Errorf("method not allowed"))
		return
	}

	a.logger.Info(fmt.Sprintf("%s called", endorsementEndpoint))

	var req tspb.GetKeyEndorsementRequest
	body, err := io.ReadAll(r.Body)
	if err != nil {
		a.logAndWriteHTTPError(w, http.StatusBadRequest, fmt.Errorf("failed to read request body: %v", err))
		return
	}

	if err := protojson.Unmarshal(body, &req); err != nil {
		a.logAndWriteHTTPError(w, http.StatusBadRequest, fmt.Errorf("failed to decode request: %v", err))
		return
	}

	if len(req.Challenge) == 0 {
		a.logAndWriteHTTPError(w, http.StatusBadRequest, fmt.Errorf("challenge is required"))
		return
	}

	if len(req.KeyHandle.Handle) == 0 {
		a.logAndWriteHTTPError(w, http.StatusBadRequest, fmt.Errorf("key_handle is required"))
		return
	}

	kemKeyClaims, err := a.keyClaimsProvider.GetKeyClaims(a.ctx, req.KeyHandle.Handle, keymanager.KeyType_KEY_TYPE_VM_PROTECTION_KEY)
	if err != nil {
		a.logAndWriteHTTPError(w, http.StatusInternalServerError, fmt.Errorf("failed to get KEM key claims"))
		return
	}

	bindingKeyClaims, err := a.keyClaimsProvider.GetKeyClaims(a.ctx, req.KeyHandle.Handle, keymanager.KeyType_KEY_TYPE_VM_PROTECTION_BINDING)
	if err != nil {
		a.logAndWriteHTTPError(w, http.StatusInternalServerError, fmt.Errorf("failed to get binding key claims"))
		return
	}

	bindingBytes, err := proto.Marshal(bindingKeyClaims)
	if err != nil {
		a.logAndWriteHTTPError(w, http.StatusInternalServerError, fmt.Errorf("failed to marshal binding key claims: %v", err))
		return
	}

	kemBytes, err := proto.Marshal(kemKeyClaims)
	if err != nil {
		a.logAndWriteHTTPError(w, http.StatusInternalServerError, fmt.Errorf("failed to marshal KEM key claims: %v", err))
		return
	}

	kemEvidence, err := a.attestAgent.AttestationEvidence(a.ctx, req.Challenge, kemBytes, agent.AttestAgentOpts{})
	if err != nil {
		a.logAndWriteHTTPError(w, http.StatusInternalServerError, fmt.Errorf("failed to collect attestation evidence with kem key claims"))
		return
	}

	bindingEvidence, err := a.attestAgent.AttestationEvidence(a.ctx, req.Challenge, bindingBytes, agent.AttestAgentOpts{})
	if err != nil {
		a.logAndWriteHTTPError(w, http.StatusInternalServerError, fmt.Errorf("failed to collect attestation evidence with binding key claims"))
		return
	}

	keyEndorsement := &attestationpb.KeyEndorsement{
		Endorsement: &attestationpb.KeyEndorsement_VmProtectedKeyEndorsement{
			VmProtectedKeyEndorsement: &attestationpb.VmProtectedKeyEndorsement{
				BindingKeyAttestation: &attestationpb.KeyAttestation{
					Attestation: bindingEvidence,
				},
				ProtectedKeyAttestation: &attestationpb.KeyAttestation{
					Attestation: kemEvidence,
				},
			},
		},
	}

	keyEndorsementBytes, err := protojson.Marshal(keyEndorsement)
	if err != nil {
		a.logAndWriteHTTPError(w, http.StatusInternalServerError, fmt.Errorf("failed to marshal evidence: %v", err))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(keyEndorsementBytes)
}

func (a *attestHandler) attest(w http.ResponseWriter, r *http.Request, client verifier.Client) {
	switch r.Method {
	case http.MethodGet:
		if err := a.attestAgent.Refresh(a.ctx); err != nil {
			a.logAndWriteHTTPError(w, http.StatusInternalServerError, fmt.Errorf("failed to refresh attestation agent: %w", err))
			return
		}

		token, err := a.attestAgent.AttestWithClient(a.ctx, agent.AttestAgentOpts{
			DeviceReportOpts: &agent.DeviceReportOpts{EnableRuntimeGPUAttestation: true},
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
			TokenOptions:     &tokenOptions,
			DeviceReportOpts: &agent.DeviceReportOpts{EnableRuntimeGPUAttestation: true},
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

func (a *attestHandler) getHostAttestation(w http.ResponseWriter, r *http.Request) {
	if !a.launchSpec.Experiments.EnableHostAttestation {
		a.logAndWriteHTTPError(w, http.StatusForbidden, fmt.Errorf("host attestation not enabled"))
		return
	}

	if r.Method != http.MethodPost {
		a.logAndWriteHTTPError(w, http.StatusMethodNotAllowed, fmt.Errorf("method not allowed"))
		return
	}

	a.logger.Info(fmt.Sprintf("%s called", hostAttestationEndpoint))

	var req tspb.GetHostAttestationRequest
	body, err := io.ReadAll(r.Body)
	if err != nil {
		a.logAndWriteHTTPError(w, http.StatusBadRequest, fmt.Errorf("failed to read request body: %v", err))
		return
	}
	if err := protojson.Unmarshal(body, &req); err != nil {
		a.logAndWriteHTTPError(w, http.StatusBadRequest, fmt.Errorf("failed to decode request: %v", err))
		return
	}
	if len(req.Challenge) == 0 {
		a.logAndWriteHTTPError(w, http.StatusBadRequest, fmt.Errorf("challenge is required"))
		return
	}

	evidence := dummyHostAttestation(req.Challenge)

	evidenceBytes, err := protojson.Marshal(evidence)
	if err != nil {
		a.logAndWriteHTTPError(w, http.StatusInternalServerError, fmt.Errorf("failed to marshal evidence: %v", err))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(evidenceBytes)
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
