package util

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
)

// Application Default Credentials (ADC) is a strategy used by the Google authentication libraries to automatically find credentials based on the application environment.
// ADC searches for credentials in GOOGLE_APPLICATION_CREDENTIALS environment variable first (https://cloud.google.com/docs/authentication/application-default-credentials)
// We use fakeAsHostEnv to let ADC find fake credential.
const fakeAsHostEnv = "GOOGLE_APPLICATION_CREDENTIALS"

// MockOauth2Server  is a struct for mocking Oauth2Server
type MockOauth2Server struct {
	Server           *httptest.Server
	OldFakeAsHostEnv string
}

// NewMockOauth2Server creates a mock Oauth2 server for testing purpose
func NewMockOauth2Server() (*MockOauth2Server, error) {
	mux := http.NewServeMux()
	mux.HandleFunc("/o/oauth2/auth", func(_ http.ResponseWriter, _ *http.Request) {
		// Unimplemented: Should return authorization code back to the user
	})

	mux.HandleFunc("/token", func(w http.ResponseWriter, _ *http.Request) {
		// Should return acccess token back to the user
		w.Header().Set("Content-Type", "application/x-www-form-urlencoded")
		w.Write([]byte("access_token=mocktoken&scope=user&token_type=bearer"))
	})

	server := httptest.NewServer(mux)

	// create test oauth2 credentials
	testCredentials := map[string]string{
		"client_id":     "id",
		"client_secret": "testdata",
		"refresh_token": "testdata",
		"type":          "authorized_user",
	}

	credentialsData, err := json.MarshalIndent(testCredentials, "", "  ") // Indent for readability
	if err != nil {
		return nil, err
	}

	file, err := os.Create("/tmp/test_credentials")
	if err != nil {
		return nil, err
	}
	defer file.Close()

	_, err = file.Write(credentialsData)
	if err != nil {
		return nil, err
	}

	old := os.Getenv(fakeAsHostEnv)
	os.Setenv(fakeAsHostEnv, "/tmp/test_credentials")

	return &MockOauth2Server{Server: server, OldFakeAsHostEnv: old}, nil
}

// Stop shuts down the server.
func (s *MockOauth2Server) Stop() {
	os.Remove("/tmp/test_credentials")
	os.Setenv(fakeAsHostEnv, s.OldFakeAsHostEnv)
	s.Server.Close()
}
