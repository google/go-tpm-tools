// Package launcher provides the entry point and core orchestration logic for the TEE container launcher.
package launcher

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
)

// GoogleRootsPath is the path to the Google roots PEM file on the OEM partition.
const GoogleRootsPath = "/usr/share/oem/google_roots.pem"

// PinnedHTTPClient creates an HTTP client configured with the provided root certificate pool.
func PinnedHTTPClient(pool *x509.CertPool) (*http.Client, error) {
	if pool == nil {
		return nil, fmt.Errorf("cert pool must be non-nil")
	}

	// We copy the default transport so we get all the proxy, keep-alive,
	// and timeout default settings, but overwrite the TLSClientConfig.RootCAs.
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

// GoogleCertPool loads the Google root certificates into an x509.CertPool.
func GoogleCertPool() (*x509.CertPool, error) {
	return loadCertPool(GoogleRootsPath)
}

func loadCertPool(rootsPath string) (*x509.CertPool, error) {
	rootsPEM, err := os.ReadFile(rootsPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read Google roots bundle at %q: %w", rootsPath, err)
	}

	pool := x509.NewCertPool()
	if ok := pool.AppendCertsFromPEM(rootsPEM); !ok {
		return nil, fmt.Errorf("failed to parse Google roots bundle from %q: no valid certificates found", rootsPath)
	}
	return pool, nil
}
