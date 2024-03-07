package util

import (
	"net/http"
	"net/http/httptest"
)

// MockOauth2Server  is a struct for mocking Oauth2Server
type MockOauth2Server struct {
	Server *httptest.Server
}

// NewMockOauth2Server creates a mock Oauth2 server for testing purpose
func NewMockOauth2Server() *MockOauth2Server {
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

	return &MockOauth2Server{Server: server}
}

// Stop shuts down the server.
func (s *MockOauth2Server) Stop() {
	s.Server.Close()
}
