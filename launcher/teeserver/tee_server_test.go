package teeserver

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"strings"
	"testing"

	"github.com/google/go-tpm-tools/cel"
	"github.com/google/go-tpm-tools/launcher/agent"
	"github.com/google/go-tpm-tools/launcher/internal/logging"
	"github.com/google/go-tpm-tools/launcher/launcherfile"
	"github.com/google/go-tpm-tools/verifier"
)

type fakeAttestationAgent struct {
	measureEventFunc func(cel.Content) error
	attestFunc       func(context.Context, agent.AttestAgentOpts) ([]byte, error)
}

func (f fakeAttestationAgent) Attest(c context.Context, a agent.AttestAgentOpts) ([]byte, error) {
	return f.attestFunc(c, a)
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
func (f fakeAttestationAgent) AddClient(client verifier.Client, verifier agent.VerifierType) error {
	return nil
}

func (f fakeAttestationAgent) HasClient(_ agent.VerifierType) bool {
	return false
}

func TestGetDefaultToken(t *testing.T) {
	tmpDir := t.TempDir()
	tmpToken := path.Join(tmpDir, launcherfile.AttestationVerifierTokenFilename)
	// An empty attestHandler is fine for now as it is not being used
	// in the handler.
	ah := attestHandler{defaultTokenFile: tmpToken,
		logger: logging.SimpleLogger(),
		attestAgent: fakeAttestationAgent{
			attestFunc: func(context.Context, agent.AttestAgentOpts) ([]byte, error) {
				t.Errorf("This method should not be called")
				return nil, nil
			},
		}}

	req := httptest.NewRequest(http.MethodGet, "/v1/token", nil)
	w := httptest.NewRecorder()
	ah.getToken(w, req)
	_, err := io.ReadAll(w.Result().Body)
	if err != nil {
		t.Error(err)
	}

	// The token file doesn't exist yet, expect a 404
	if w.Code != http.StatusNotFound {
		t.Errorf("got return code: %d, want: %d", w.Code, http.StatusNotFound)
	}

	// create a fake test token file
	testTokenContent := "test token"
	os.WriteFile(tmpToken, []byte(testTokenContent), 0644)

	// retry calling the handler, and now it should return the token file content
	w = httptest.NewRecorder()
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
		testName   string
		body       string
		attestFunc func(context.Context, agent.AttestAgentOpts) ([]byte, error)
		want       int
	}{
		{
			testName: "TestNoAudiencePostRequest",
			body: `{
				"audience": "",
				"nonces": ["thisIsAcustomNonce"],
				"token_type": "OIDC"
				}`,
			attestFunc: func(context.Context, agent.AttestAgentOpts) ([]byte, error) {
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
			attestFunc: func(context.Context, agent.AttestAgentOpts) ([]byte, error) {
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
			attestFunc: func(context.Context, agent.AttestAgentOpts) ([]byte, error) {
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
			attestFunc: func(context.Context, agent.AttestAgentOpts) ([]byte, error) {
				return []byte{}, nil
			},
			want: http.StatusOK,
		},
	}

	for i, test := range tests {
		tmpDir := t.TempDir()
		tmpToken := path.Join(tmpDir, launcherfile.AttestationVerifierTokenFilename)
		// An empty attestHandler is fine for now as it is not being used
		// in the handler.
		ah := attestHandler{defaultTokenFile: tmpToken,
			logger: logging.SimpleLogger(),
			attestAgent: fakeAttestationAgent{
				attestFunc: test.attestFunc,
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
