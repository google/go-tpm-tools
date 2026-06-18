// Package teeserver implements a server to be run in the launcher.
// Used for communicate between the host/launcher and the container.
package teeserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"

	attestationpb "github.com/GoogleCloudPlatform/confidential-space/server/proto/gen/attestation"
	"github.com/google/go-tpm-tools/agent"
	wsd "github.com/google/go-tpm-tools/keymanager/workload_service"
	"github.com/google/go-tpm-tools/launcher/internal/logging"
	"github.com/google/go-tpm-tools/launcher/spec"
	tspb "github.com/google/go-tpm-tools/launcher/teeserver/proto/gen/teeserver"
	"github.com/google/go-tpm-tools/verifier"
	"github.com/google/go-tpm-tools/verifier/models"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
)

const (
	gcaEndpoint               = "/v1/token"
	itaEndpoint               = "/v1/intel/token"
	evidenceEndpoint          = "/v1/evidence"
	endorsementEndpoint       = "/v1/keys:getEndorsement"
	hostAttestationEndpoint   = "/v1/hostAttestation"
	kpsAttestationServiceAddr = "192.168.100.3:50051"
	wsdSocket                 = "/tmp/container_launcher/kmaserver-grpc.sock"
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
	logger             logging.Logger
	launchSpec         spec.LaunchSpec
	clients            AttestClients
	keyClaimsProvider  wsd.KeyClaimsProvider
	kemAttester        KeyEndorsementAttester
	bindingKeyAttester KeyEndorsementAttester
}

// TeeServer is a server that can be called from a container through a unix
// socket file.
type TeeServer struct {
	server             *http.Server
	netListener        net.Listener
	kemAttester        KeyEndorsementAttester
	bindingKeyAttester KeyEndorsementAttester
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

	kemAttester, err := initKEMAttester(launchSpec.Experiments.BcMode, keyClaimsProvider, a)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize KEM attester: %v", err)
	}

	bindingKeyAttester, err := initBindingKeyAttester(launchSpec.Experiments.BcMode, keyClaimsProvider, a)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize binding key attester: %v", err)
	}

	teeServer := TeeServer{
		netListener:        nl,
		kemAttester:        kemAttester,
		bindingKeyAttester: bindingKeyAttester,
		server: &http.Server{
			Handler: (&attestHandler{
				ctx:                ctx,
				attestAgent:        a,
				logger:             logger,
				launchSpec:         launchSpec,
				clients:            clients,
				keyClaimsProvider:  keyClaimsProvider,
				kemAttester:        kemAttester,
				bindingKeyAttester: bindingKeyAttester,
			}).Handler(),
		},
	}
	return &teeServer, nil
}

func initKEMAttester(bcMode bool, keyClaimsProvider wsd.KeyClaimsProvider, a agent.AttestationAgent) (KeyEndorsementAttester, error) {
	if !bcMode {
		return newLocalKEMAttester(keyClaimsProvider, a), nil
	}
	conn, err := grpc.NewClient(kpsAttestationServiceAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("failed to initialize remote KEM attester: %v", err)
	}
	// Early initiate the connection in the background. By default, grpc.NewClient
	// creates a client in the IDLE state and only connects on the first RPC call.
	// This can cause the first HTTP request to getEndorsement to hang and time out
	// during the initial TCP/HTTP2 handshake.
	conn.Connect()
	return newRemoteKEMAttester(conn), nil
}

func initBindingKeyAttester(bcMode bool, keyClaimsProvider wsd.KeyClaimsProvider, a agent.AttestationAgent) (KeyEndorsementAttester, error) {
	if !bcMode {
		return newLocalBindingKeyAttester(keyClaimsProvider, a), nil
	}

	conn, err := grpc.NewClient(
		"unix://"+wsdSocket,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create remote server client via unix socket %s: %v", wsdSocket, err)
	}
	// Early initiate the connection in the background. By default, grpc.NewClient
	// creates a client in the IDLE state and only connects on the first RPC call.
	// This can cause the first HTTP request to getEndorsement to hang and time out
	// during the initial TCP/HTTP2 handshake.
	conn.Connect()
	return newBCBindingKeyAttester(conn, a), nil
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

	var mask *fieldmaskpb.FieldMask
	if qMask := r.URL.Query().Get("read_mask"); qMask != "" {
		mask = &fieldmaskpb.FieldMask{Paths: strings.Split(qMask, ",")}
	} else if qMask := r.URL.Query().Get("readMask"); qMask != "" {
		mask = &fieldmaskpb.FieldMask{Paths: strings.Split(qMask, ",")}
	} else if qMask := r.URL.Query().Get("fields"); qMask != "" {
		mask = &fieldmaskpb.FieldMask{Paths: strings.Split(qMask, ",")}
	} else if qMask := r.URL.Query().Get("$fields"); qMask != "" {
		mask = &fieldmaskpb.FieldMask{Paths: strings.Split(qMask, ",")}
	} else if hMask := r.Header.Get("X-Goog-FieldMask"); hMask != "" {
		mask = &fieldmaskpb.FieldMask{Paths: strings.Split(hMask, ",")}
	} else if req.ReadMask != nil {
		mask = req.ReadMask
	}

	enableGPU := false
	if mask != nil {
		for _, path := range mask.GetPaths() {
			if path == "*" || path == "deviceReports" || path == "device_reports" ||
				strings.HasPrefix(path, "deviceReports.") || strings.HasPrefix(path, "device_reports.") {
				enableGPU = true
				break
			}
		}
	}

	attestOpts := agent.AttestAgentOpts{
		DeviceReportOpts: &agent.DeviceReportOpts{
			EnableRuntimeGPUAttestation: enableGPU,
		},
	}
	evidence, err := a.attestAgent.AttestationEvidence(a.ctx, req.Challenge, nil, attestOpts)
	if err != nil {
		a.logAndWriteHTTPError(w, http.StatusInternalServerError, err)
		return
	}

	partialEvidence, err := filterVMAttestationFields(evidence, mask)
	if err != nil {
		a.logAndWriteHTTPError(w, http.StatusBadRequest, fmt.Errorf("invalid read_mask: %v", err))
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

// filterVMAttestationFields return a partial VM Attestation based on the field mask.
func filterVMAttestationFields(att *attestationpb.VmAttestation, mask *fieldmaskpb.FieldMask) (*attestationpb.VmAttestation, error) {
	if mask == nil || len(mask.GetPaths()) == 0 {
		out := proto.Clone(att).(*attestationpb.VmAttestation)
		out.DeviceReports = nil
		return out, nil
	}

	for _, path := range mask.GetPaths() {
		if path == "*" {
			return att, nil
		}
	}

	fieldMap := make(map[string]bool)
	for _, path := range mask.GetPaths() {
		fieldMap[strings.TrimSpace(path)] = true
	}

	out := &attestationpb.VmAttestation{}
	if fieldMap["label"] {
		out.Label = att.GetLabel()
	}
	if fieldMap["challenge"] {
		out.Challenge = att.GetChallenge()
	}
	if fieldMap["extraData"] || fieldMap["extra_data"] {
		out.ExtraData = att.GetExtraData()
	}
	if fieldMap["quote"] {
		out.Quote = att.GetQuote()
	}
	if fieldMap["deviceReports"] || fieldMap["device_reports"] {
		out.DeviceReports = att.GetDeviceReports()
	}
	return out, nil
}

// getKeyEndorsement retrieves the attestation evidence with KEM and binding key claims.
func (a *attestHandler) getKeyEndorsement(w http.ResponseWriter, r *http.Request) {
	if !a.launchSpec.Experiments.EnableKeyManager && !a.launchSpec.Experiments.BcMode {
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

	attestOpts := agent.AttestAgentOpts{
		AcpiOpts: &agent.AcpiOpts{
			RetrieveAcpiData: req.GetRequestAcpiData(),
		},
	}

	bindingKeyEvidence, err := a.bindingKeyAttester.GetKeyEndorsement(a.ctx, &req, attestOpts)
	if err != nil {
		a.logAndWriteHTTPError(w, http.StatusInternalServerError, fmt.Errorf("failed to collect attestation evidence with binding key claims"))
		return
	}

	kemEvidence, err := a.kemAttester.GetKeyEndorsement(a.ctx, &req, attestOpts)
	if err != nil {
		a.logAndWriteHTTPError(w, http.StatusInternalServerError, fmt.Errorf("failed to collect KEM evidence: %v", err))
		return
	}

	keyEndorsement := &attestationpb.KeyEndorsement{
		Endorsement: &attestationpb.KeyEndorsement_VmProtectedKeyEndorsement{
			VmProtectedKeyEndorsement: &attestationpb.VmProtectedKeyEndorsement{
				BindingKeyAttestation: &attestationpb.KeyAttestation{
					Attestation: bindingKeyEvidence,
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

	evidence := &attestationpb.HostAttestation{}
	if !a.launchSpec.Experiments.BcMode {
		// vg has host attestation enabled and should use dummy implementation
		evidence = dummyHostAttestation(req.Challenge)
	} else {
		hostAttBytes, err := a.attestAgent.AttestHost(a.ctx, req.Challenge)
		if err != nil {
			a.logAndWriteHTTPError(w, http.StatusInternalServerError, fmt.Errorf("failed to fetch host attestation: %v", err))
			return
		}
		if err := proto.Unmarshal(hostAttBytes, evidence); err != nil {
			a.logAndWriteHTTPError(w, http.StatusInternalServerError, fmt.Errorf("failed to unmarshal host attestation: %v", err))
			return
		}
	}

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
	var errs []error
	if err := s.server.Shutdown(ctx); err != nil {
		errs = append(errs, err)
	}
	if err := s.netListener.Close(); err != nil {
		errs = append(errs, err)
	}
	if s.kemAttester != nil {
		if err := s.kemAttester.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if s.bindingKeyAttester != nil {
		if err := s.bindingKeyAttester.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
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
