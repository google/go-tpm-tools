package cmd

import (
	"net/http"
	"net/http/httptest"
)

type oauth2Server struct {
	server *httptest.Server
}

func newMockOauth2Server() *oauth2Server {
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

	return &oauth2Server{server: server}
}

// Stop shuts down the server.
func (s *oauth2Server) Stop() {
	s.server.Close()
}
