// Package teeserver implements a server to be run in the launcher.
// Used for communicate between the host/launcher and the container.
package teeserver

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"

	attestationpb "github.com/GoogleCloudPlatform/confidential-space/server/proto/gen/attestation"
	keymanager "github.com/google/go-tpm-tools/keymanager/km_common/proto"
	wsd "github.com/google/go-tpm-tools/keymanager/workload_service"
	"github.com/google/go-tpm-tools/launcher/agent"
	"github.com/google/go-tpm-tools/launcher/internal/logging"
	"github.com/google/go-tpm-tools/launcher/spec"
	"github.com/google/go-tpm-tools/verifier"
	"github.com/google/go-tpm-tools/verifier/models"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

const (
	gcaEndpoint         = "/v1/token"
	itaEndpoint         = "/v1/intel/token"
	evidenceEndpoint    = "/v1/evidence"
	endorsementEndpoint = "/v1/keys:getEndorsement"
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
	UnimplementedTeeServerServer
	ctx               context.Context
	attestAgent       agent.AttestationAgent
	logger            logging.Logger
	launchSpec        spec.LaunchSpec
	clients           AttestClients
	keyClaimsProvider wsd.KeyClaimsProvider
}

// TeeServer is a server that can be called from a container through a unix
// socket file.
type TeeServer struct {
	server       *http.Server
	netListener  net.Listener
	grpcServer   *grpc.Server
	grpcListener net.Listener
}


// New takes in two sockets and starts to listen to them, and creates both HTTP and gRPC servers.
func New(ctx context.Context, unixSock string, grpcSock string, a agent.AttestationAgent, logger logging.Logger, launchSpec spec.LaunchSpec, clients AttestClients, keyClaimsProvider wsd.KeyClaimsProvider) (*TeeServer, error) {
	nl, err := net.Listen("unix", unixSock)
	if err != nil {
		return nil, fmt.Errorf("cannot listen to the socket [%s]: %v", unixSock, err)
	}

	gnl, err := net.Listen("unix", grpcSock)
	if err != nil {
		nl.Close()
		return nil, fmt.Errorf("cannot listen to the grpc socket [%s]: %v", grpcSock, err)
	}

	if launchSpec.Experiments.EnableKeyManager && keyClaimsProvider == nil {
		nl.Close()
		gnl.Close()
		return nil, fmt.Errorf("key claims provider cannot be nil when key manager is enabled")
	}

	handler := &attestHandler{
		ctx:               ctx,
		attestAgent:       a,
		logger:            logger,
		launchSpec:        launchSpec,
		clients:           clients,
		keyClaimsProvider: keyClaimsProvider,
	}

	gs := grpc.NewServer()
	RegisterTeeServerServer(gs, handler)

	teeServer := TeeServer{
		netListener: nl,
		server: &http.Server{
			Handler: handler.Handler(),
		},
		grpcListener: gnl,
		grpcServer:   gs,
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
func (a *attestHandler) getAttestationEvidence(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		a.logAndWriteHTTPError(w, http.StatusMethodNotAllowed, fmt.Errorf("method not allowed"))
		return
	}

	var req GetAttestationEvidenceRequest
	body, err := io.ReadAll(r.Body)
	if err != nil {
		a.logAndWriteHTTPError(w, http.StatusInternalServerError, fmt.Errorf("failed to read body: %v", err))
		return
	}
	if err := protojson.Unmarshal(body, &req); err != nil {
		a.logAndWriteHTTPError(w, http.StatusBadRequest, fmt.Errorf("failed to decode request: %v", err))
		return
	}

	resp, err := a.GetAttestationEvidence(a.ctx, &req)
	if err != nil {
		a.handleAttestError(w, err, "failed to get attestation evidence")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(resp.Evidence)
}

// getKeyEndorsement retrieves the attestation evidence with KEM and binding key claims.
func (a *attestHandler) getKeyEndorsement(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		a.logAndWriteHTTPError(w, http.StatusMethodNotAllowed, fmt.Errorf("method not allowed"))
		return
	}

	var req GetKeyEndorsementRequest
	body, err := io.ReadAll(r.Body)
	if err != nil {
		a.logAndWriteHTTPError(w, http.StatusInternalServerError, fmt.Errorf("failed to read body: %v", err))
		return
	}
	if err := protojson.Unmarshal(body, &req); err != nil {
		a.logAndWriteHTTPError(w, http.StatusBadRequest, fmt.Errorf("failed to decode request: %v", err))
		return
	}

	resp, err := a.GetKeyEndorsement(a.ctx, &req)
	if err != nil {
		a.handleAttestError(w, err, "failed to get key endorsement")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(resp.Endorsement)
}

func (a *attestHandler) attest(w http.ResponseWriter, r *http.Request, client verifier.Client) {
	var req GetTokenRequest
	switch r.Method {
	case http.MethodGet:
		// Default token case, req is empty.
	case http.MethodPost:
		body, err := io.ReadAll(r.Body)
		if err != nil {
			a.logAndWriteHTTPError(w, http.StatusInternalServerError, fmt.Errorf("failed to read body: %v", err))
			return
		}
		if err := protojson.Unmarshal(body, &req); err != nil {
			a.logAndWriteHTTPError(w, http.StatusBadRequest, fmt.Errorf("failed to decode request: %v", err))
			return
		}
		// Validate token options in POST
		if req.Audience == "" {
			a.logAndWriteHTTPError(w, http.StatusBadRequest, fmt.Errorf("use GET request for the default identity token"))
			return
		}
		if req.TokenType == "" {
			a.logAndWriteHTTPError(w, http.StatusBadRequest, fmt.Errorf("token_type is a required parameter"))
			return
		}
	default:
		a.logAndWriteHTTPError(w, http.StatusMethodNotAllowed, fmt.Errorf("TEE server received an invalid HTTP method: %s", r.Method))
		return
	}

	var token []byte
	var err error
	if client == a.clients.GCA {
		var resp *GetTokenResponse
		resp, err = a.GetToken(a.ctx, &req)
		if resp != nil {
			token = resp.Token
		}
	} else if client == a.clients.ITA {
		var resp *GetTokenResponse
		resp, err = a.GetITAToken(a.ctx, &req)
		if resp != nil {
			token = resp.Token
		}
	} else {
		err = fmt.Errorf("unknown verifier client")
	}

	if err != nil {
		a.handleAttestError(w, err, "failed to retrieve attestation service token")
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(token)
}

			

func (a *attestHandler) handleAttestError(w http.ResponseWriter, err error, message string) {
	st, ok := status.FromError(err)
	if ok {
		switch st.Code() {
		case codes.InvalidArgument, codes.FailedPrecondition:
			a.logAndWriteHTTPError(w, http.StatusBadRequest, fmt.Errorf("%s: %w", message, err))
		case codes.PermissionDenied:
			a.logAndWriteHTTPError(w, http.StatusForbidden, fmt.Errorf("%s: %w", message, err))
		case codes.Unauthenticated:
			a.logAndWriteHTTPError(w, http.StatusUnauthorized, fmt.Errorf("%s: %w", message, err))
		case codes.NotFound:
			a.logAndWriteHTTPError(w, http.StatusNotFound, fmt.Errorf("%s: %w", message, err))
		default:
			a.logAndWriteHTTPError(w, http.StatusInternalServerError, fmt.Errorf("%s: %w", message, err))
		}
		return
	}
	// If it's not a gRPC error, it's likely an internal error within the launcher.
	// Map user errors 500 Internal Server Error
	a.logAndWriteHTTPError(w, http.StatusInternalServerError, fmt.Errorf("%s: %w", message, err))
}

func (a *attestHandler) logAndWriteHTTPError(w http.ResponseWriter, statusCode int, err error) {
	a.logger.Error(err.Error())
	w.WriteHeader(statusCode)
	w.Write([]byte(err.Error()))
}

// Serve starts the servers, will block until the servers shutdown.
func (s *TeeServer) Serve() error {
	errCh := make(chan error, 2)
	go func() {
		errCh <- s.server.Serve(s.netListener)
	}()
	go func() {
		errCh <- s.grpcServer.Serve(s.grpcListener)
	}()

	return <-errCh
}

// Shutdown will terminate the servers and their underlying listeners.
func (s *TeeServer) Shutdown(ctx context.Context) error {
	var errs []error
	if err := s.server.Shutdown(ctx); err != nil {
		errs = append(errs, fmt.Errorf("http server shutdown error: %v", err))
	}
	s.grpcServer.GracefulStop()

	if err := s.netListener.Close(); err != nil {
		errs = append(errs, fmt.Errorf("http listener close error: %v", err))
	}
	if err := s.grpcListener.Close(); err != nil {
		errs = append(errs, fmt.Errorf("grpc listener close error: %v", err))
	}

	if len(errs) > 0 {
		return fmt.Errorf("shutdown errors: %v", errs)
	}
	return nil
}


func (a *attestHandler) GetToken(ctx context.Context, req *GetTokenRequest) (*GetTokenResponse, error) {
	if a.clients.GCA == nil {
		return nil, status.Error(codes.FailedPrecondition, "no GCA verifier client present, please try rebooting your VM")
	}
	token, err := a.attestInternal(ctx, a.clients.GCA, req)
	if err != nil {
		return nil, err
	}
	return &GetTokenResponse{Token: token}, nil
}

func (a *attestHandler) GetITAToken(ctx context.Context, req *GetTokenRequest) (*GetTokenResponse, error) {
	if a.clients.ITA == nil {
		return nil, status.Error(codes.FailedPrecondition, "no ITA verifier client present - ensure ITA Region and Key are defined in metadata")
	}
	token, err := a.attestInternal(ctx, a.clients.ITA, req)
	if err != nil {
		return nil, err
	}
	return &GetTokenResponse{Token: token}, nil
}

func (a *attestHandler) GetAttestationEvidence(ctx context.Context, req *GetAttestationEvidenceRequest) (*GetAttestationEvidenceResponse, error) {
	if len(req.Challenge) == 0 {
		return nil, status.Error(codes.InvalidArgument, "challenge is required")
	}
	evidence, err := a.attestAgent.AttestationEvidence(ctx, req.Challenge, nil)
	if err != nil {
		return nil, err
	}
	evidenceBytes, err := protojson.Marshal(evidence)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to marshal evidence: %v", err)
	}
	return &GetAttestationEvidenceResponse{Evidence: evidenceBytes}, nil
}

func (a *attestHandler) GetKeyEndorsement(ctx context.Context, req *GetKeyEndorsementRequest) (*GetKeyEndorsementResponse, error) {
	if !a.launchSpec.Experiments.EnableKeyManager {
		return nil, status.Error(codes.PermissionDenied, "keymanager not enabled")
	}
	if len(req.Challenge) == 0 {
		return nil, status.Error(codes.InvalidArgument, "challenge is required")
	}
	if req.KeyHandle == nil || req.KeyHandle.Handle == "" {
		return nil, status.Error(codes.InvalidArgument, "key_handle is required")
	}

	kemKeyClaims, err := a.keyClaimsProvider.GetKeyClaims(ctx, req.KeyHandle.Handle, keymanager.KeyType_KEY_TYPE_VM_PROTECTION_KEY)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get KEM key claims: %v", err)
	}

	bindingKeyClaims, err := a.keyClaimsProvider.GetKeyClaims(ctx, req.KeyHandle.Handle, keymanager.KeyType_KEY_TYPE_VM_PROTECTION_BINDING)

	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get binding key claims: %v", err)
	}

	bindingBytes, err := proto.Marshal(bindingKeyClaims)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to marshal binding key claims: %v", err)
	}

	kemBytes, err := proto.Marshal(kemKeyClaims)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to marshal KEM key claims: %v", err)
	}

	kemEvidence, err := a.attestAgent.AttestationEvidence(ctx, req.Challenge, kemBytes)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to collect attestation evidence with kem key claims: %v", err)
	}

	bindingEvidence, err := a.attestAgent.AttestationEvidence(ctx, req.Challenge, bindingBytes)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to collect attestation evidence with binding key claims: %v", err)
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
		return nil, status.Errorf(codes.Internal, "failed to marshal evidence: %v", err)
	}

	return &GetKeyEndorsementResponse{Endorsement: keyEndorsementBytes}, nil
}

func (a *attestHandler) attestInternal(ctx context.Context, client verifier.Client, req *GetTokenRequest) ([]byte, error) {
	if client == nil {
		return nil, status.Error(codes.Internal, "verifier client is nil")
	}

	opts := a.mapToTokenOptions(req)

	if opts != nil {
		if opts.Audience == "" && len(opts.Nonces) == 0 {
			// Special case for refresh: if audience/nonces are empty, it's a "default" refresh request.
			// However, in our new API, we prefer explicit requests.
			// Matches existing behavior if we want to allow it.
		}
	} else {
		// Default token case (GET in HTTP)
		if err := a.attestAgent.Refresh(ctx); err != nil {
			return nil, status.Errorf(codes.Internal, "failed to refresh attestation agent: %v", err)
		}
	}

	token, err := a.attestAgent.AttestWithClient(ctx, agent.AttestAgentOpts{TokenOptions: opts}, client)
	if err != nil {
		return nil, err
	}
	return token, nil
}

func (a *attestHandler) mapToTokenOptions(req *GetTokenRequest) *models.TokenOptions {
	if req == nil {
		return &models.TokenOptions{}
	}

	res := &models.TokenOptions{
		Audience:  req.Audience,
		Nonces:    req.Nonces,
		TokenType: req.TokenType,
	}

	if req.AwsPrincipalTagOptions != nil {
		res.PrincipalTagOptions = &models.AWSPrincipalTagsOptions{}
		if req.AwsPrincipalTagOptions.AllowedPrincipalTags != nil {
			res.PrincipalTagOptions.AllowedPrincipalTags = &models.AllowedPrincipalTags{}
			if req.AwsPrincipalTagOptions.AllowedPrincipalTags.ContainerImageSignatures != nil {
				res.PrincipalTagOptions.AllowedPrincipalTags.ContainerImageSignatures = &models.ContainerImageSignatures{
					KeyIDs: req.AwsPrincipalTagOptions.AllowedPrincipalTags.ContainerImageSignatures.KeyIds,
				}
			}
		}
	}
	return res
}

