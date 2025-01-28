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
)

// Implements verifier.Client interface so it can be used to initialize test attestHandlers
type fakeVerifierClient struct{}

func (f *fakeVerifierClient) CreateChallenge(ctx context.Context) (*verifier.Challenge, error) {
	return nil, fmt.Errorf("unimplemented")
}

func (f *fakeVerifierClient) VerifyAttestation(ctx context.Context, request verifier.VerifyAttestationRequest) (*verifier.VerifyAttestationResponse, error) {
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

	// An empty attestHandler is fine for now as it is not being used
	// in the handler.
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
	if string(data) != testTokenContent {
		t.Errorf("got content: %v, want: %s", testTokenContent, string(data))
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
			want: http.StatusBadRequest,
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
			attestFunc: func(context.Context, agent.AttestAgentOpts) ([]byte, error) {
				return []byte{}, nil
			},
			want: http.StatusOK,
		},
	}

	for i, test := range tests {
		// An empty attestHandler is fine for now as it is not being used
		// in the handler.
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
		tmpDir := t.TempDir()
		tmpToken := path.Join(tmpDir, launcherfile.AttestationVerifierTokenFilename)
		ah := attestHandler{defaultTokenFile: tmpToken,
			logger: logging.SimpleLogger(),
			attestAgent: fakeAttestationAgent{
				attestFunc: func(_ context.Context, gotOpts agent.AttestAgentOpts) ([]byte, error) {
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
