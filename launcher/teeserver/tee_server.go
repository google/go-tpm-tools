// Package teeserver implements a server to be run in the launcher.
// Used for communicate between the host/launcher and the container.
package teeserver

import (
	"context"
	"crypto/sha512"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"

	"cloud.google.com/go/compute/metadata"
	"cloud.google.com/go/logging"
	"github.com/google/go-tpm-tools/launcher/agent"
	"github.com/google/go-tpm-tools/launcher/launcherfile"
	"github.com/google/go-tpm-tools/verifier/oci"
)

type attestHandler struct {
	ctx              context.Context
	attestAgent      agent.AttestationAgent
	defaultTokenFile string
	logger           *log.Logger
	cloudLogger      *logging.Logger
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
func New(ctx context.Context, unixSock string, a agent.AttestationAgent, logger *log.Logger) (*TeeServer, error) {
	var err error
	nl, err := net.Listen("unix", unixSock)
	if err != nil {
		return nil, fmt.Errorf("cannot listen to the socket [%s]: %v", unixSock, err)
	}

	// Configure Cloud Logging client.
	mdsClient := metadata.NewClient(nil)

	projectID, err := mdsClient.ProjectIDWithContext(ctx)
	if err != nil {
		return nil, err
	}

	// Configure Cloud Logging client/logger.
	cloudLogger, err := logging.NewClient(ctx, projectID)
	if err != nil {
		return nil, err
	}

	teeServer := TeeServer{
		netListener: nl,
		server: &http.Server{
			Handler: (&attestHandler{
				ctx:              ctx,
				attestAgent:      a,
				defaultTokenFile: filepath.Join(launcherfile.HostTmpPath, launcherfile.AttestationVerifierTokenFilename),
				logger:           logger,
				cloudLogger:      cloudLogger.Logger("ita-prototype-image"),
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
	mux.HandleFunc("/v1/evidence", a.getEvidence)
	return mux
}

// getDefaultToken handles the request to get the default OIDC token.
// For now this function will just read the content of the file and return.
// Later, this function can use attestation agent to get a token directly.
func (a *attestHandler) getToken(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")

	switch r.Method {
	case "GET":
		// this could call Attest(ctx) directly later.
		data, err := os.ReadFile(a.defaultTokenFile)

		if err != nil {
			a.logger.Print(err)
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
			a.logger.Print(err)
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
			a.logger.Print(err)
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

type itaNonce struct {
	Val       []byte `json:"val"`
	Iat       []byte `json:"iat"`
	Signature []byte `json:"signature"`
}

type evidenceRequest struct {
	Nonce itaNonce `json:"nonce"`
}

type confidentialSpaceInfo struct {
	SignedEntities []oci.Signature `json:"signed_entities,omitempty"`
}

type gcpEvidence struct {
	GcpCredentials        [][]byte              `json:"gcp_credentials,omitempty"`
	ConfidentialSpaceInfo confidentialSpaceInfo `json:"confidential_space_info,omitempty"`
	AkCert                []byte                `json:"ak_cert,omitempty"`
	IntermediateCerts     [][]byte              `json:"intermediate_certs,omitempty"`
}

type tdxAttestation struct {
	CcelAcpiTable     []byte `json:"ccel_table,omitempty"`
	CcelData          []byte `json:"ccel_data,omitempty"`
	TdQuote           []byte `json:"quote"`
	CanonicalEventLog []byte `json:"canonical_event_log,omitempty"`
}

type tdxEvidence struct {
	Attestation tdxAttestation `json:"attestation,omitempty"`
	GcpData     gcpEvidence    `json:"gcp_data,omitempty"`
}

func processITANonce(input itaNonce) ([]byte, error) {
	if len(input.Val) == 0 {
		return nil, fmt.Errorf("no value in nonce")
	}

	if len(input.Iat) == 0 {
		return nil, fmt.Errorf("no iat in nonce")
	}

	nonce := append(input.Val, input.Iat...)

	hash := sha512.New()
	_, err := hash.Write(nonce)
	if err != nil {
		return nil, err
	}

	return hash.Sum(nil), nil
}

func (a *attestHandler) getEvidence(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case "GET":
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("use POST request for evidence"))
		return
	case "POST":
		var evidenceReq evidenceRequest
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()

		err := decoder.Decode(&evidenceReq)
		if err != nil {
			a.logger.Printf(err.Error())
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(err.Error()))
			return
		}

		nonce, err := processITANonce(evidenceReq.Nonce)
		if err != nil {
			a.logger.Print(err.Error())
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(err.Error()))
			return
		}

		evidence, err := a.attestAgent.AttestationEvidence(nonce, "ita://"+string(evidenceReq.Nonce.Val))
		if err != nil {
			a.logger.Print(err.Error())
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(err.Error()))
			return
		}

		// Check for TDX Attestation.
		if evidence.TDXAttestation == nil {
			err_msg := "getEvidence is only supported for TDX Attestation"
			a.logger.Print(err_msg)
			w.WriteHeader(http.StatusPreconditionFailed)
			w.Write([]byte(err_msg))
			return
		}

		tdxEvi := &tdxEvidence{
			Attestation: tdxAttestation{
				TdQuote:           evidence.TDXAttestation.TdQuote,
				CcelData:          evidence.TDXAttestation.CcelData,
				CanonicalEventLog: evidence.TDXAttestation.CanonicalEventLog,
			},
			GcpData: gcpEvidence{
				GcpCredentials:    evidence.PrincipalTokens,
				AkCert:            evidence.TDXAttestation.AkCert,
				IntermediateCerts: evidence.TDXAttestation.IntermediateCerts,
				ConfidentialSpaceInfo: confidentialSpaceInfo{
					SignedEntities: evidence.ContainerSignatures,
				},
			},
		}

		logEntry := logging.Entry{
			Severity: logging.Info,
			Payload:  tdxEvi,
		}

		a.cloudLogger.Log(logEntry)
		a.cloudLogger.Flush()

		jsonData, err := json.Marshal(tdxEvi)
		if err != nil {
			err_msg := "error marshalling response"
			a.logger.Print(err_msg)
			w.WriteHeader(http.StatusPreconditionFailed)
			w.Write([]byte(err_msg))
			return
		}

		// Check if output file exists.
		filename := "/tmp/container_launcher/ita_evidence"
		_, err = os.Stat(filename)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			w.WriteHeader(http.StatusPreconditionFailed)
			w.Write([]byte(err.Error()))
			return
		} else if err == nil {
			os.Remove(filename)
		}

		// Create output file.
		f, err := os.Create(filename)
		if err != nil {
			fmt.Printf("failed to create output file: %v", err)
			w.WriteHeader(http.StatusPreconditionFailed)
			w.Write([]byte(err.Error()))
			return
		}
		defer f.Close()

		// Write to output file.
		_, err = f.WriteString(string(jsonData))
		if err != nil {
			fmt.Printf("failed to write to output file: %v", err)
			w.WriteHeader(http.StatusPreconditionFailed)
			w.Write([]byte(err.Error()))
			return
		}

		w.WriteHeader(http.StatusOK)
		w.Write(jsonData)
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
