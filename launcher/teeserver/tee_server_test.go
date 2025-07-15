package teeserver

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-tpm-tools/cel"
	"github.com/google/go-tpm-tools/launcher/agent"
	"github.com/google/go-tpm-tools/launcher/internal/logging"
	"github.com/google/go-tpm-tools/verifier"
	"github.com/google/go-tpm-tools/verifier/models"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Implements verifier.Client interface so it can be used to initialize test attestHandlers
type fakeVerifierClient struct{}

func (f *fakeVerifierClient) CreateChallenge(_ context.Context) (*verifier.Challenge, error) {
	return nil, fmt.Errorf("unimplemented")
}

func (f *fakeVerifierClient) VerifyAttestation(_ context.Context, _ verifier.VerifyAttestationRequest) (*verifier.VerifyAttestationResponse, error) {
	return nil, fmt.Errorf("unimplemented")
}

type fakeAttestationAgent struct {
	measureEventFunc     func(cel.Content) error
	attestFunc           func(context.Context, agent.AttestAgentOpts) ([]byte, error)
	attestWithClientFunc func(context.Context, agent.AttestAgentOpts, verifier.Client) ([]byte, error)
}

func (f fakeAttestationAgent) Attest(c context.Context, a agent.AttestAgentOpts) ([]byte, error) {
	return f.attestFunc(c, a)
}

func (f fakeAttestationAgent) AttestWithClient(c context.Context, a agent.AttestAgentOpts, v verifier.Client) ([]byte, error) {
	return f.attestWithClientFunc(c, a, v)
}

func (f fakeAttestationAgent) MeasureEvent(c cel.Content) error {
	return f.measureEventFunc(c)
}

func (f fakeAttestationAgent) Refresh(_ context.Context) error {
	return nil
}

func (f fakeAttestationAgent) Close() error {
	return nil
}

func TestGetDefaultToken(t *testing.T) {
	testTokenContent := "test token"

	ah := attestHandler{
		logger: logging.SimpleLogger(),
		clients: &AttestClients{
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
	// An empty attestHandler is fine for now as it is not being used
	// in the handler.
	ah := attestHandler{
		logger: logging.SimpleLogger(),
		clients: &AttestClients{
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
				return []byte{}, nil
			},
			want: http.StatusOK,
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

	for i, test := range tests {
		ah := attestHandler{
			logger: logging.SimpleLogger(),
			clients: &AttestClients{
				GCA: &fakeVerifierClient{},
			},
			attestAgent: fakeAttestationAgent{
				attestWithClientFunc: test.attestWithClientFunc,
			}}

		b := strings.NewReader(test.body)

		req := httptest.NewRequest(http.MethodPost, "/v1/token", b)
		w := httptest.NewRecorder()
		ah.getToken(w, req)
		_, err := io.ReadAll(w.Result().Body)
		if err != nil {
			t.Error(err)
		}

		if w.Code != test.want {
			t.Errorf("testcase %d, '%v': got return code: %d, want: %d", i, test.testName, w.Code, test.want)
		}
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
			},
		},
	}

	for i, test := range tests {
		ah := attestHandler{
			logger: logging.SimpleLogger(),
			clients: &AttestClients{
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
				clients: &AttestClients{
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
