// Package teeserver implements a server to be run in the launcher.
// Used for communicate between the host/launcher and the container.
package teeserver

import (
	"context"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
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
	ctx              context.Context
	attestAgent      agent.AttestationAgent
	defaultTokenFile string
	logger           *log.Logger
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

func trimCCELData(data []byte) []byte {
	trimIndex := len(data)
	for ; trimIndex >= 0; trimIndex-- {
		c := data[trimIndex-1]
		// Proceed until 0xFF padding ends.
		if c != byte(255) {
			break
		}
	}

	return data[:trimIndex]
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

		tdxEvi := &tokenRequest{
			PolicyMatch: true,
			TDX: tdxEvidence{
				Quote:             evidence.TDXAttestation.TdQuote,
				CcelData:          trimCCELData(evidence.TDXAttestation.CcelData),
				CanonicalEventLog: evidence.TDXAttestation.CanonicalEventLog,
			},
			SigAlg: "RS256",
			GCP: gcpData{
				GcpCredentials:    []string{},
				AKCert:            evidence.TDXAttestation.AkCert,
				IntermediateCerts: evidence.TDXAttestation.IntermediateCerts,
				CSInfo: confidentialSpaceInfo{
					SignedEntities: make([]containerSignature, len(evidence.ContainerSignatures)),
					TokenOpts: tokenOptions{
						Audience:  "custom-audience",
						Nonces:    []string{"nonce1", "nonce2"},
						TokenType: "OIDC",
						TokenTypeOpts: tokenTypeOptions{
							AllowedPrincipalTags: principalTags{
								ContainerSignatureKIDs: keyIDs{
									map[string][]string{
										"key_ids": {"kid1", "kid2"},
									},
								},
							},
						},
					},
				},
			},
		}

		for _, token := range evidence.PrincipalTokens {
			tdxEvi.GCP.GcpCredentials = append(tdxEvi.GCP.GcpCredentials, string(token))
		}

		for i, sig := range evidence.ContainerSignatures {
			sigPayload, err := sig.Payload()
			if err != nil {
				a.logger.Print(err.Error())
				w.WriteHeader(http.StatusPreconditionFailed)
				w.Write([]byte(err.Error()))
				return
			}

			b64Sig, err := sig.Base64Encoded()
			if err != nil {
				a.logger.Print(err.Error())
				w.WriteHeader(http.StatusPreconditionFailed)
				w.Write([]byte(err.Error()))
				return
			}

			sigBytes, err := base64.StdEncoding.DecodeString(b64Sig)
			if err != nil {
				a.logger.Print(err.Error())
				w.WriteHeader(http.StatusPreconditionFailed)
				w.Write([]byte(err.Error()))
				return
			}

			tdxEvi.GCP.CSInfo.SignedEntities[i] = containerSignature{sigPayload, sigBytes}
		}

		a.logger.Printf("%+v\n", tdxEvi)

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
