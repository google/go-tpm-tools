// Package tlsutil provides utilities for configuring TLS connections with custom trust roots.
package tlsutil

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
)

// GoogleRootsPath is the path to the Google roots PEM file.
const GoogleRootsPath = "/usr/share/oem/google_roots.pem"

// GoogleHTTPClient creates an HTTP client that only trusts the roots required for connecting to Google.
func GoogleHTTPClient() (*http.Client, error) {
	return googleHTTPClientWithRoots(GoogleRootsPath)
}

// googleHTTPClientWithRoots allows internal tests to inject mock certificate paths.
func googleHTTPClientWithRoots(rootsPath string) (*http.Client, error) {
	rootsPEM, err := os.ReadFile(rootsPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read Google roots bundle at %q: %w", rootsPath, err)
	}

	pool := x509.NewCertPool()
	if ok := pool.AppendCertsFromPEM(rootsPEM); !ok {
		return nil, fmt.Errorf("failed to parse Google roots bundle from %q: no valid certificates found", rootsPath)
	}

	// We copy the default transport so we get all the proxy, keep-alive,
	// and timeout default settings, but overwrite the TLSClientConfig.RootCAs
	defaultTransport, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return nil, fmt.Errorf("http.DefaultTransport is not of type *http.Transport")
	}

	customTransport := defaultTransport.Clone()
	if customTransport.TLSClientConfig == nil {
		customTransport.TLSClientConfig = &tls.Config{}
	}
	customTransport.TLSClientConfig.RootCAs = pool

	return &http.Client{
		Transport: customTransport,
	}, nil
}
