package teeserver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	gecel "github.com/google/go-eventlog/cel"
	"github.com/google/go-tpm-tools/agent"
	keymanager "github.com/google/go-tpm-tools/keymanager/km_common/proto"
	"github.com/google/go-tpm-tools/launcher/internal/experiments"
	"github.com/google/go-tpm-tools/launcher/internal/logging"
	"github.com/google/go-tpm-tools/launcher/spec"
	"github.com/google/go-tpm-tools/verifier"
	"github.com/google/go-tpm-tools/verifier/models"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	attestationpb "github.com/GoogleCloudPlatform/confidential-space/server/proto/gen/attestation"
	"google.golang.org/protobuf/testing/protocmp"
)

// Implements verifier.Client interface so it can be used to initialize test attestHandlers
type fakeVerifierClient struct{}

func (f *fakeVerifierClient) CreateChallenge(_ context.Context) (*verifier.Challenge, error) {
	return nil, fmt.Errorf("unimplemented")
}

func (f *fakeVerifierClient) VerifyAttestation(_ context.Context, _ verifier.VerifyAttestationRequest) (*verifier.VerifyAttestationResponse, error) {
	return nil, fmt.Errorf("unimplemented")
}

func (f *fakeVerifierClient) VerifyConfidentialSpace(_ context.Context, _ verifier.VerifyAttestationRequest) (*verifier.VerifyAttestationResponse, error) {
	return nil, fmt.Errorf("unimplemented")
}

type fakeAttestationAgent struct {
	measureEventFunc        func(gecel.Content) error
	attestFunc              func(context.Context, agent.AttestAgentOpts) ([]byte, error)
	attestWithClientFunc    func(context.Context, agent.AttestAgentOpts, verifier.Client) ([]byte, error)
	attestationEvidenceFunc func(context.Context, []byte, []byte) (*attestationpb.VmAttestation, error)
}

func (f fakeAttestationAgent) Attest(c context.Context, a agent.AttestAgentOpts) ([]byte, error) {
	return f.attestFunc(c, a)
}

func (f fakeAttestationAgent) AttestWithClient(c context.Context, a agent.AttestAgentOpts, v verifier.Client) ([]byte, error) {
	return f.attestWithClientFunc(c, a, v)
}

func (f fakeAttestationAgent) AttestationEvidence(c context.Context, nonce []byte, extraData []byte, opts agent.AttestAgentOpts) (*attestationpb.VmAttestation, error) {
	attestation, err := f.attestationEvidenceFunc(c, nonce, extraData)
	if err != nil {
		return nil, err
	}
	if opts.DeviceReportOpts != nil && opts.DeviceReportOpts.EnableRuntimeGPUAttestation {
		attestation.DeviceReports = append(attestation.DeviceReports, &attestationpb.DeviceAttestationReport{
			Report: &attestationpb.DeviceAttestationReport_NvidiaReport{
				NvidiaReport: &attestationpb.NvidiaAttestationReport{},
			},
		})
	}
	return attestation, nil
}

func (f fakeAttestationAgent) MeasureEvent(c gecel.Content) error {
	return f.measureEventFunc(c)
}

func (f fakeAttestationAgent) Refresh(_ context.Context) error {
	return nil
}

func (f fakeAttestationAgent) Close() error {
	return nil
}

// Mock for KeyClaimsProvider interface
type mockClaimsProvider struct {
	claims map[keymanager.KeyType]*keymanager.KeyClaims
	err    error
}

func (m *mockClaimsProvider) GetKeyClaims(_ context.Context, _ string, kt keymanager.KeyType) (*keymanager.KeyClaims, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.claims[kt], nil
}

func TestGetDefaultToken(t *testing.T) {
	testTokenContent := "test token"

	ah := attestHandler{
		logger: logging.SimpleLogger(),
		clients: AttestClients{
			GCA: &fakeVerifierClient{},
		},
		attestAgent: fakeAttestationAgent{
			attestWithClientFunc: func(context.Context, agent.AttestAgentOpts, verifier.Client) ([]byte, error) {
				return []byte(testTokenContent), nil
			},
		}}

	req := httptest.NewRequest(http.MethodGet, "/v1/token", nil)
	w := httptest.NewRecorder()

	ah.getToken(w, req)
	data, err := io.ReadAll(w.Result().Body)
	if err != nil {
		t.Error(err)
	}

	if w.Code != http.StatusOK {
		t.Errorf("got return code: %d, want: %d", w.Code, http.StatusOK)
	}
	if diff := cmp.Diff(testTokenContent, string(data)); diff != "" {
		t.Errorf("getToken() response body mismatch (-want +got):\n%s", diff)
	}
}

func TestGetDefaultTokenServerError(t *testing.T) {
	ah := attestHandler{
		logger: logging.SimpleLogger(),
		clients: AttestClients{
			GCA: &fakeVerifierClient{},
		},
		attestAgent: fakeAttestationAgent{
			attestWithClientFunc: func(context.Context, agent.AttestAgentOpts, verifier.Client) ([]byte, error) {
				return nil, errors.New("internal server error from agent")
			},
		}}

	req := httptest.NewRequest(http.MethodGet, "/v1/token", nil)
	w := httptest.NewRecorder()

	ah.getToken(w, req)
	data, err := io.ReadAll(w.Result().Body)
	if err != nil {
		t.Error(err)
	}

	if w.Code != http.StatusInternalServerError {
		t.Errorf("got return code: %d, want: %d", w.Code, http.StatusInternalServerError)
	}
	expectedError := "failed to retrieve attestation service token: internal server error from agent"
	if diff := cmp.Diff(expectedError, string(data)); diff != "" {
		t.Errorf("getToken() response body mismatch (-want +got):\n%s", diff)
	}
}

func TestCustomToken(t *testing.T) {
	tests := []struct {
		testName             string
		body                 string
		attestWithClientFunc func(context.Context, agent.AttestAgentOpts, verifier.Client) ([]byte, error)
		want                 int
	}{
		{
			testName: "TestNoAudiencePostRequest",
			body: `{
				"audience": "",
				"nonces": ["thisIsAcustomNonce"],
				"token_type": "OIDC"
				}`,
			attestWithClientFunc: func(context.Context, agent.AttestAgentOpts, verifier.Client) ([]byte, error) {
				t.Errorf("This method should not be called")
				return nil, nil
			},
			want: http.StatusBadRequest,
		},
		{
			testName: "TestRequestFailurePassedToCaller",
			body: `{
				"audience": "audience",
				"nonces": ["thisIsAcustomNonce"],
				"token_type": "OIDC"
			}`,
			attestWithClientFunc: func(context.Context, agent.AttestAgentOpts, verifier.Client) ([]byte, error) {
				return nil, errors.New("Error")
			},
			want: http.StatusInternalServerError,
		},
		{
			testName: "TestTokenTypeRequired",
			body: `{
				"audience": "audience",
				"nonces": ["thisIsAcustomNonce"],
				"token_type": ""
			}`,
			attestWithClientFunc: func(context.Context, agent.AttestAgentOpts, verifier.Client) ([]byte, error) {
				t.Errorf("This method should not be called")
				return nil, nil
			},
			want: http.StatusBadRequest,
		},
		{
			testName: "TestRequestSuccessPassedToCaller",
			body: `{
				"audience": "audience",
				"nonces": ["thisIsAcustomNonce"],
				"token_type": "OIDC"
			}`,
			attestWithClientFunc: func(context.Context, agent.AttestAgentOpts, verifier.Client) ([]byte, error) {
				return []byte{}, nil
			},
			want: http.StatusOK,
		},
		{
			testName: "TestPrincipalTagOptionsSuccess",
			body: `{
				"audience": "audience",
				"nonces": ["thisIsAcustomNonce"],
				"token_type": "OIDC",
				"aws_principal_tag_options" : {
					"allowed_principal_tags": {
						"container_image_signatures" : {
							"key_ids": ["test1", "test2"]
						}
					}
				}
			}`,
			attestWithClientFunc: func(context.Context, agent.AttestAgentOpts, verifier.Client) ([]byte, error) {
				return []byte{}, nil
			},
			want: http.StatusOK,
		},
	}

	verifiers := []struct {
		name        string
		url         string
		tokenMethod func(ah *attestHandler, w http.ResponseWriter, r *http.Request)
	}{
		{
			name:        "GCA Handler",
			url:         "/v1/token",
			tokenMethod: (*attestHandler).getToken,
		},
		{
			name:        "ITA Handler",
			url:         "/v1/intel/token",
			tokenMethod: (*attestHandler).getITAToken,
		},
	}

	for _, vf := range verifiers {
		t.Run(vf.name, func(t *testing.T) {
			for _, test := range tests {
				ah := attestHandler{
					logger: logging.SimpleLogger(),
					clients: AttestClients{
						GCA: &fakeVerifierClient{},
						ITA: &fakeVerifierClient{},
					},
					attestAgent: fakeAttestationAgent{
						attestWithClientFunc: test.attestWithClientFunc,
					}}

				b := strings.NewReader(test.body)

				req := httptest.NewRequest(http.MethodPost, vf.url, b)
				w := httptest.NewRecorder()

				vf.tokenMethod(&ah, w, req)

				_, err := io.ReadAll(w.Result().Body)
				if err != nil {
					t.Error(err)
				}

				if w.Code != test.want {
					t.Errorf("testcase '%v': got return code: %d, want: %d", test.testName, w.Code, test.want)
				}
			}
		})
	}
}

func TestHandleAttestError(t *testing.T) {
	body := `{
				"audience": "audience",
				"nonces": ["thisIsAcustomNonce"],
				"token_type": "OIDC"
			}`

	errorCases := []struct {
		name           string
		err            error
		wantStatusCode int
	}{
		{
			name:           "FailedPrecondition error",
			err:            status.New(codes.FailedPrecondition, "bad state").Err(),
			wantStatusCode: http.StatusBadRequest,
		},
		{
			name:           "PermissionDenied error",
			err:            status.New(codes.PermissionDenied, "denied").Err(),
			wantStatusCode: http.StatusBadRequest,
		},
		{
			name:           "Internal error",
			err:            status.New(codes.Internal, "internal server error").Err(),
			wantStatusCode: http.StatusInternalServerError,
		},
		{
			name:           "Unavailable error",
			err:            status.New(codes.Unavailable, "service unavailable").Err(),
			wantStatusCode: http.StatusInternalServerError,
		},
		{
			name:           "non-gRPC error",
			err:            errors.New("a generic error"),
			wantStatusCode: http.StatusInternalServerError,
		},
	}

	verifiers := []struct {
		name        string
		url         string
		tokenMethod func(ah *attestHandler, w http.ResponseWriter, r *http.Request)
	}{
		{
			name:        "GCA Handler",
			url:         "/v1/token",
			tokenMethod: (*attestHandler).getToken,
		},
		{
			name:        "ITA Handler",
			url:         "/v1/intel/token",
			tokenMethod: (*attestHandler).getITAToken,
		},
	}

	for _, vf := range verifiers {
		t.Run(vf.name, func(t *testing.T) {
			for _, tc := range errorCases {
				t.Run(tc.name, func(t *testing.T) {
					ah := attestHandler{
						logger: logging.SimpleLogger(),
						clients: AttestClients{
							GCA: &fakeVerifierClient{},
							ITA: &fakeVerifierClient{},
						},
						attestAgent: fakeAttestationAgent{
							attestWithClientFunc: func(context.Context, agent.AttestAgentOpts, verifier.Client) ([]byte, error) {
								return nil, tc.err
							},
						},
					}

					req := httptest.NewRequest(http.MethodPost, vf.url, strings.NewReader(body))
					w := httptest.NewRecorder()

					vf.tokenMethod(&ah, w, req)

					if w.Code != tc.wantStatusCode {
						t.Errorf("got status code %d, want %d", w.Code, tc.wantStatusCode)
					}

					_, err := io.ReadAll(w.Result().Body)
					if err != nil {
						t.Errorf("failed to read response body: %v", err)
					}
				})
			}
		})
	}
}

func TestHandleAttestError_NilClient(t *testing.T) {
	verifiers := []struct {
		name    string
		url     string
		handler func(ah *attestHandler, w http.ResponseWriter, r *http.Request)
	}{
		{name: "GCA Handler", url: "/v1/token", handler: (*attestHandler).getToken},
		{name: "ITA Handler", url: "/v1/intel/token", handler: (*attestHandler).getITAToken},
	}

	for _, vf := range verifiers {
		t.Run(vf.name, func(t *testing.T) {
			ah := attestHandler{
				logger:  logging.SimpleLogger(),
				clients: AttestClients{}, // No clients defined
			}

			req := httptest.NewRequest(http.MethodPost, vf.url, strings.NewReader(""))
			w := httptest.NewRecorder()
			vf.handler(&ah, w, req)

			const wantStatusCode = http.StatusInternalServerError
			if w.Code != wantStatusCode {
				t.Errorf("got status code %d, want %d", w.Code, wantStatusCode)
			}
		})
	}
}

func TestCustomTokenDataParsedSuccessfully(t *testing.T) {
	tests := []struct {
		testName   string
		body       string
		attestFunc func(context.Context, agent.AttestAgentOpts) ([]byte, error)
		wantCode   int
		wantOpts   agent.AttestAgentOpts
	}{
		{
			testName: "TestKeyIdsReadSuccessfullyEvenWithInvalidTokenTypeMatch",
			body: `{
				"audience": "audience",
				"nonces": ["thisIsAcustomNonce"],
				"token_type": "OIDC",
				"aws_principal_tag_options" : {
					"allowed_principal_tags": {
						"container_image_signatures" : {
							"key_ids": ["test1", "test2"]
						}
					}
				}
			}`,
			wantCode: http.StatusOK,
			wantOpts: agent.AttestAgentOpts{
				TokenOptions: &models.TokenOptions{
					Audience:  "audience",
					Nonces:    []string{"thisIsAcustomNonce"},
					TokenType: "OIDC",
					PrincipalTagOptions: &models.AWSPrincipalTagsOptions{
						AllowedPrincipalTags: &models.AllowedPrincipalTags{
							ContainerImageSignatures: &models.ContainerImageSignatures{
								KeyIDs: []string{"test1", "test2"},
							},
						},
					},
				},
				DeviceReportOpts: &agent.DeviceReportOpts{EnableRuntimeGPUAttestation: true},
			},
		},
		{
			testName: "PartialAwsPrincipalTagOptionsOK",
			body: `{
				"audience": "audience",
				"nonces": ["thisIsAcustomNonce"],
				"token_type": "OIDC",
				"aws_principal_tag_options" : {
				}
			}`,
			wantCode: http.StatusOK,
			wantOpts: agent.AttestAgentOpts{
				TokenOptions: &models.TokenOptions{
					Audience:            "audience",
					Nonces:              []string{"thisIsAcustomNonce"},
					TokenType:           "OIDC",
					PrincipalTagOptions: &models.AWSPrincipalTagsOptions{},
				},
				DeviceReportOpts: &agent.DeviceReportOpts{EnableRuntimeGPUAttestation: true},
			},
		},
		{
			testName: "MorePartialAwsPrincipalTagOptionsOK",
			body: `{
				"audience": "audience",
				"nonces": ["thisIsAcustomNonce"],
				"token_type": "OIDC",
				"aws_principal_tag_options" : {
					"allowed_principal_tags": {
					}
				}
			}`,
			wantCode: http.StatusOK,
			wantOpts: agent.AttestAgentOpts{
				TokenOptions: &models.TokenOptions{
					Audience:  "audience",
					Nonces:    []string{"thisIsAcustomNonce"},
					TokenType: "OIDC",
					PrincipalTagOptions: &models.AWSPrincipalTagsOptions{
						AllowedPrincipalTags: &models.AllowedPrincipalTags{},
					},
				},
				DeviceReportOpts: &agent.DeviceReportOpts{EnableRuntimeGPUAttestation: true},
			},
		},
		{
			testName: "InvalidJSONNotOkay",
			body: `{
				"audience": "audience",
				"nonces": ["thisIsAcustomNonce"],
				"token_type": "OIDC",
				"aws_principal_tag_options" : {
					"allowed_principal_tag": {
					}
				}
			}`,
			wantCode: http.StatusBadRequest,
			wantOpts: agent.AttestAgentOpts{
				TokenOptions: &models.TokenOptions{
					Audience:  "audience",
					Nonces:    []string{"thisIsAcustomNonce"},
					TokenType: "OIDC",
					PrincipalTagOptions: &models.AWSPrincipalTagsOptions{
						AllowedPrincipalTags: &models.AllowedPrincipalTags{},
					},
				},
				DeviceReportOpts: &agent.DeviceReportOpts{EnableRuntimeGPUAttestation: true},
			},
		},
	}

	for i, test := range tests {
		ah := attestHandler{
			logger: logging.SimpleLogger(),
			clients: AttestClients{
				GCA: &fakeVerifierClient{},
			},
			attestAgent: fakeAttestationAgent{
				attestWithClientFunc: func(_ context.Context, gotOpts agent.AttestAgentOpts, _ verifier.Client) ([]byte, error) {
					diff := cmp.Diff(test.wantOpts, gotOpts)
					if diff != "" {
						t.Errorf("%v: got unexpected agent.AttestAgentOpts. diff:\n%v", test.testName, diff)
					}
					return []byte{}, nil
				},
			}}

		b := strings.NewReader(test.body)

		req := httptest.NewRequest(http.MethodPost, "/v1/token", b)
		w := httptest.NewRecorder()
		ah.getToken(w, req)
		_, err := io.ReadAll(w.Result().Body)
		if err != nil {
			t.Error(err)
		}

		if w.Code != test.wantCode {
			t.Errorf("testcase %d, '%v': got return code: %d, want: %d", i, test.testName, w.Code, test.wantCode)
		}
	}
}

func TestCustomHandleAttestError(t *testing.T) {
	body := `{
				"audience": "audience",
				"nonces": ["thisIsAcustomNonce"],
				"token_type": "OIDC"
			}`

	testcases := []struct {
		name           string
		err            error
		wantStatusCode int
	}{
		{
			name:           "FailedPrecondition error",
			err:            status.New(codes.FailedPrecondition, "bad state").Err(),
			wantStatusCode: http.StatusBadRequest,
		},
		{
			name:           "PermissionDenied error",
			err:            status.New(codes.PermissionDenied, "denied").Err(),
			wantStatusCode: http.StatusBadRequest,
		},
		{
			name:           "Internal error",
			err:            status.New(codes.Internal, "internal server error").Err(),
			wantStatusCode: http.StatusInternalServerError,
		},
		{
			name:           "Unavailable error",
			err:            status.New(codes.Unavailable, "service unavailable").Err(),
			wantStatusCode: http.StatusInternalServerError,
		},
		{
			name:           "non-gRPC error",
			err:            errors.New("a generic error"),
			wantStatusCode: http.StatusInternalServerError,
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			ah := attestHandler{
				logger: logging.SimpleLogger(),
				clients: AttestClients{
					GCA: &fakeVerifierClient{},
				},
				attestAgent: fakeAttestationAgent{
					attestWithClientFunc: func(context.Context, agent.AttestAgentOpts, verifier.Client) ([]byte, error) {
						return nil, tc.err
					},
				},
			}

			req := httptest.NewRequest(http.MethodPost, "/v1/token", strings.NewReader(body))
			w := httptest.NewRecorder()

			ah.getToken(w, req)

			if w.Code != tc.wantStatusCode {
				t.Errorf("got status code %d, want %d", w.Code, tc.wantStatusCode)
			}

			_, err := io.ReadAll(w.Result().Body)
			if err != nil {
				t.Errorf("failed to read response body: %v", err)
			}
		})
	}
}

func TestAttestationEvidence(t *testing.T) {
	testAttestation := &attestationpb.VmAttestation{
		Label:     []byte("test-label"),
		Challenge: []byte("test-challenge"),
		ExtraData: []byte("test-extra-data"),
		Quote: &attestationpb.VmAttestationQuote{
			Quote: &attestationpb.VmAttestationQuote_TdxCcelQuote{
				TdxCcelQuote: &attestationpb.TdxCcelQuote{},
			},
		},
	}

	testCases := []struct {
		name                    string
		method                  string
		url                     string
		body                    string
		attestationEvidenceFunc func(context.Context, []byte, []byte) (*attestationpb.VmAttestation, error)
		wantStatusCode          int
		wantBodyContains        string
	}{
		{
			name:           "success no fields",
			method:         http.MethodPost,
			url:            "/v1/evidence",
			body:           `{"challenge": "dGVzdA=="}`,
			wantStatusCode: http.StatusOK,
			attestationEvidenceFunc: func(_ context.Context, _ []byte, _ []byte) (*attestationpb.VmAttestation, error) {
				return testAttestation, nil
			},
			wantBodyContains: `{"label":"dGVzdC1sYWJlbA==","challenge":"dGVzdC1jaGFsbGVuZ2U=","extraData":"dGVzdC1leHRyYS1kYXRh","quote":{"tdxCcelQuote":{}}}`,
		},
		{
			name:           "success with * fields",
			method:         http.MethodPost,
			url:            "/v1/evidence?fields=*",
			body:           `{"challenge": "dGVzdA=="}`,
			wantStatusCode: http.StatusOK,
			attestationEvidenceFunc: func(_ context.Context, _ []byte, _ []byte) (*attestationpb.VmAttestation, error) {
				return testAttestation, nil
			},
			wantBodyContains: `{"label":"dGVzdC1sYWJlbA==","challenge":"dGVzdC1jaGFsbGVuZ2U=","extraData":"dGVzdC1leHRyYS1kYXRh","quote":{"tdxCcelQuote":{}},"deviceReports":[{"nvidiaReport":{}}]}`,
		},
		{
			name:           "success with fields",
			method:         http.MethodPost,
			url:            "/v1/evidence?fields=label,quote",
			body:           `{"challenge": "dGVzdA=="}`,
			wantStatusCode: http.StatusOK,
			attestationEvidenceFunc: func(_ context.Context, _ []byte, _ []byte) (*attestationpb.VmAttestation, error) {
				return testAttestation, nil
			},
			wantBodyContains: `{"label":"dGVzdC1sYWJlbA==","quote":{"tdxCcelQuote":{}}}`,
		},
		{
			name:             "wrong method",
			method:           http.MethodGet,
			url:              "/v1/evidence",
			body:             "",
			wantStatusCode:   http.StatusMethodNotAllowed,
			wantBodyContains: "method not allowed",
		},
		{
			name:             "malformed json",
			method:           http.MethodPost,
			url:              "/v1/evidence",
			body:             `{"challenge": "dGVzdA=="`,
			wantStatusCode:   http.StatusBadRequest,
			wantBodyContains: "failed to decode request",
		},
		{
			name:             "missing challenge",
			method:           http.MethodPost,
			url:              "/v1/evidence",
			body:             `{}`,
			wantStatusCode:   http.StatusBadRequest,
			wantBodyContains: "challenge is required",
		},
		{
			name:           "attestation agent error",
			method:         http.MethodPost,
			url:            "/v1/evidence",
			body:           `{"challenge": "dGVzdA=="}`,
			wantStatusCode: http.StatusInternalServerError,
			attestationEvidenceFunc: func(_ context.Context, _ []byte, _ []byte) (*attestationpb.VmAttestation, error) {
				return nil, errors.New("agent error")
			},
			wantBodyContains: "agent error",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			attestationFunc := tc.attestationEvidenceFunc
			if attestationFunc == nil {
				attestationFunc = func(_ context.Context, _ []byte, _ []byte) (*attestationpb.VmAttestation, error) {
					return &attestationpb.VmAttestation{}, nil
				}
			}
			ah := attestHandler{
				logger: logging.SimpleLogger(),
				attestAgent: fakeAttestationAgent{
					attestationEvidenceFunc: attestationFunc,
				},
			}

			req := httptest.NewRequest(tc.method, tc.url, strings.NewReader(tc.body))
			w := httptest.NewRecorder()

			ah.getAttestationEvidence(w, req)

			if w.Code != tc.wantStatusCode {
				t.Errorf("getAttestationEvidence() got status code %d, want %d", w.Code, tc.wantStatusCode)
			}

			if tc.wantStatusCode == http.StatusOK {
				var gotEvidence attestationpb.VmAttestation
				if err := protojson.Unmarshal(w.Body.Bytes(), &gotEvidence); err != nil {
					t.Fatalf("failed to unmarshal response: %v", err)
				}
				var wantEvidence attestationpb.VmAttestation
				if err := protojson.Unmarshal([]byte(tc.wantBodyContains), &wantEvidence); err != nil {
					t.Fatalf("failed to unmarshal wantBodyContains: %v", err)
				}
				if diff := cmp.Diff(&wantEvidence, &gotEvidence, protocmp.Transform()); diff != "" {
					t.Errorf("getAttestationEvidence() response body mismatch (-want +got):\n%s", diff)
				}
			} else {
				respBody, _ := io.ReadAll(w.Body)
				if !strings.Contains(string(respBody), tc.wantBodyContains) {
					t.Errorf("getAttestationEvidence() response body = %q, want to contain %q", string(respBody), tc.wantBodyContains)
				}
			}
		})
	}
}

func TestFilterVMAttestationFields(t *testing.T) {
	fullAttestation := &attestationpb.VmAttestation{
		Label:     []byte("test-label"),
		Challenge: []byte("test-challenge"),
		ExtraData: []byte("test-extra-data"),
		Quote: &attestationpb.VmAttestationQuote{
			Quote: &attestationpb.VmAttestationQuote_TpmQuote{
				TpmQuote: &attestationpb.TpmQuote{},
			},
		},
		DeviceReports: []*attestationpb.DeviceAttestationReport{
			{
				Report: &attestationpb.DeviceAttestationReport_NvidiaReport{
					NvidiaReport: &attestationpb.NvidiaAttestationReport{},
				},
			},
		},
	}

	testCases := []struct {
		name   string
		fields string
		mutate func(att *attestationpb.VmAttestation)
		want   *attestationpb.VmAttestation
	}{
		{
			name:   "no fields",
			fields: "",
			mutate: func(att *attestationpb.VmAttestation) {
				att.DeviceReports = nil
			},
			want: &attestationpb.VmAttestation{
				Label:     fullAttestation.Label,
				Challenge: fullAttestation.Challenge,
				ExtraData: fullAttestation.ExtraData,
				Quote:     fullAttestation.Quote,
			},
		},
		{
			name:   "single field label",
			fields: "label",
			want: &attestationpb.VmAttestation{
				Label: fullAttestation.Label,
			},
		},
		{
			name:   "single field challenge",
			fields: "challenge",
			want: &attestationpb.VmAttestation{
				Challenge: fullAttestation.Challenge,
			},
		},
		{
			name:   "single field extraData",
			fields: "extraData",
			want: &attestationpb.VmAttestation{
				ExtraData: fullAttestation.ExtraData,
			},
		},
		{
			name:   "single field quote",
			fields: "quote",
			want: &attestationpb.VmAttestation{
				Quote: fullAttestation.Quote,
			},
		},
		{
			name:   "single field deviceReports",
			fields: "deviceReports",
			want: &attestationpb.VmAttestation{
				DeviceReports: fullAttestation.DeviceReports,
			},
		},
		{
			name:   "multiple fields",
			fields: "label,quote",
			want: &attestationpb.VmAttestation{
				Label: fullAttestation.Label,
				Quote: fullAttestation.Quote,
			},
		},
		{
			name:   "all fields",
			fields: "label,challenge,extraData,quote,deviceReports",
			want:   fullAttestation,
		},
		{
			name:   "fields with whitespace",
			fields: " label , deviceReports ",
			want: &attestationpb.VmAttestation{
				Label:         fullAttestation.Label,
				DeviceReports: fullAttestation.DeviceReports,
			},
		},
		{
			name:   "all fields with *",
			fields: "*",
			want:   fullAttestation,
		},
		{
			name:   "unknown fields are ignored",
			fields: "label,foo,bar",
			want: &attestationpb.VmAttestation{
				Label: fullAttestation.Label,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			attestation := proto.Clone(fullAttestation).(*attestationpb.VmAttestation)
			if tc.mutate != nil {
				tc.mutate(attestation)
			}
			got, err := filterVMAttestationFields(attestation, tc.fields)
			if err != nil {
				t.Fatalf("filterVMAttestationFields() returned an unexpected error: %v", err)
			}
			if diff := cmp.Diff(tc.want, got, protocmp.Transform()); diff != "" {
				t.Errorf("filterVMAttestationFields() returned diff (-want +got):\n%s", diff)
			}
		})
	}
}

func TestGetKeyEndorsement(t *testing.T) {
	testHandle := "66eeec4b-0b20-4b30-987b-9c46b74ecc16"
	testChallenge := []byte("test-challenge")

	tests := []struct {
		name         string
		reqBody      interface{}
		enableKM     bool
		claimsErr    error
		attestErr    error
		wantStatus   int
		expectErrMsg string
	}{
		{
			name: "success",
			reqBody: map[string]interface{}{
				"challenge":  testChallenge,
				"key_handle": map[string]string{"handle": testHandle},
			},
			enableKM:   true,
			wantStatus: http.StatusOK,
		},
		{
			name: "key manager disabled",
			reqBody: map[string]interface{}{
				"challenge":  testChallenge,
				"key_handle": map[string]string{"handle": testHandle},
			},
			enableKM:   false,
			wantStatus: http.StatusForbidden,
		},
		{
			name: "missing key handle",
			reqBody: map[string]interface{}{
				"challenge":  testChallenge,
				"key_handle": map[string]string{"handle": ""},
			},
			enableKM:   true,
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "claims provider error",
			reqBody: map[string]interface{}{
				"challenge":  testChallenge,
				"key_handle": map[string]string{"handle": testHandle},
			},
			enableKM:   true,
			claimsErr:  fmt.Errorf("internal provider error"),
			wantStatus: http.StatusInternalServerError,
		},
		{
			name: "attestation agent error",
			reqBody: map[string]interface{}{
				"challenge":  testChallenge,
				"key_handle": map[string]string{"handle": testHandle},
			},
			enableKM:   true,
			attestErr:  fmt.Errorf("tpm failure"),
			wantStatus: http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mClaims := &mockClaimsProvider{
				err: tt.claimsErr,
				claims: map[keymanager.KeyType]*keymanager.KeyClaims{
					keymanager.KeyType_KEY_TYPE_VM_PROTECTION_KEY:     {Claims: &keymanager.KeyClaims_VmKeyClaims{}},
					keymanager.KeyType_KEY_TYPE_VM_PROTECTION_BINDING: {Claims: &keymanager.KeyClaims_VmBindingClaims{}},
				},
			}
			mAgent := &fakeAttestationAgent{
				attestationEvidenceFunc: func(_ context.Context, _, b2 []byte) (*attestationpb.VmAttestation, error) {
					if tt.attestErr != nil {
						return nil, tt.attestErr
					}
					return &attestationpb.VmAttestation{ExtraData: b2}, nil
				},
			}
			handler := &attestHandler{
				ctx:               context.Background(),
				attestAgent:       mAgent,
				keyClaimsProvider: mClaims,
				logger:            logging.SimpleLogger(),
				launchSpec: spec.LaunchSpec{
					Experiments: experiments.Experiments{EnableKeyManager: tt.enableKM},
				},
			}
			body, _ := json.Marshal(tt.reqBody)
			req := httptest.NewRequest(http.MethodPost, endorsementEndpoint, bytes.NewBuffer(body))
			rr := httptest.NewRecorder()
			handler.getKeyEndorsement(rr, req)

			if rr.Code != tt.wantStatus {
				t.Errorf("%s: got status %v, want %v. Body: %s", tt.name, rr.Code, tt.wantStatus, rr.Body.String())
			}
			if tt.wantStatus == http.StatusOK {
				var endorsement attestationpb.KeyEndorsement
				if err := protojson.Unmarshal(rr.Body.Bytes(), &endorsement); err != nil {
					t.Fatalf("failed to unmarshal response: %v", err)
				}
				vmEndorsement := endorsement.GetVmProtectedKeyEndorsement()
				if vmEndorsement == nil {
					t.Fatal("response missing VmProtectedKeyEndorsement")
				}
				if vmEndorsement.BindingKeyAttestation.Attestation == nil ||
					vmEndorsement.ProtectedKeyAttestation.Attestation == nil {
					t.Error("one or both attestations are nil")
				}
			}
		})
	}
}
