package tlsutil

import (
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

func TestGoogleHTTPClientWithRoots(t *testing.T) {
	t.Run("empty path", func(t *testing.T) {
		_, err := googleHTTPClientWithRoots("")
		if err == nil {
			t.Errorf("googleHTTPClientWithRoots() expected error for empty path, got nil")
		}
	})

	t.Run("missing file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "missing.pem")
		_, err := googleHTTPClientWithRoots(path)
		if err == nil {
			t.Errorf("googleHTTPClientWithRoots() expected error for missing file, got nil")
		}
	})

	t.Run("malformed pem", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "malformed.pem")
		if err := os.WriteFile(path, []byte("-----BEGIN CERTIFICATE-----\nBAD\n-----END CERTIFICATE-----"), 0644); err != nil {
			t.Fatalf("failed to create malformed file: %v", err)
		}

		_, err := googleHTTPClientWithRoots(path)
		if err == nil {
			t.Errorf("googleHTTPClientWithRoots() expected error for malformed pem, got nil")
		}
	})

	t.Run("valid pem", func(t *testing.T) {
		validPEM := `-----BEGIN CERTIFICATE-----
MIIDczCCAlugAwIBAgIUC1mdNsdB4jmUzAB7WdcMybyxXI8wDQYJKoZIhvcNAQEL
BQAwSTELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkNBMQswCQYDVQQHDAJTRjENMAsG
A1UECgwEVGVzdDERMA8GA1UEAwwIdGVzdC5jb20wHhcNMjYwNjA0MTgyMjAwWhcN
MjcwNjA0MTgyMjAwWjBJMQswCQYDVQQGEwJVUzELMAkGA1UECAwCQ0ExCzAJBgNV
BAcMAlNGMQ0wCwYDVQQKDARUZXN0MREwDwYDVQQDDAh0ZXN0LmNvbTCCASIwDQYJ
KoZIhvcNAQEBBQADggEPADCCAQoCggEBANKeU3d0HUzqx/4uONKgsnK+1GzvxqOI
rSL/CDez53MiPAnnRdc6EJHR0OTzjbCXyfWL1vFcMMbYHT1uT8KM106c56vwYObb
TRxcA3WNImbCFRLCKrGQilBoEJYfwGee1ickMb1NbrlFWEtXa+GT9WLKLcg0lWen
2bdf4E7gghwkNj4Cub9TBF6vZSvbHwm8Ih/KLGgP985HNHiYAAwAkLAQ8iO+x2oU
O/JZqeIv0mLHgIvlbrv5pdF3Oo/d5PkRVS4lqgXH9BAfsf64T7VEb4AWmkadXgVo
/jlm7jBLT165zGfqpAtY525kABiYGD/uIeqzoEfP7h9XOBGI8PLaN7cCAwEAAaNT
MFEwHQYDVR0OBBYEFGoh2THvsCQMut95N5cfF92FUwyJMB8GA1UdIwQYMBaAFGoh
2THvsCQMut95N5cfF92FUwyJMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQEL
BQADggEBAJx+/18F/QHmhDHp2mf+7quqsYX3fKjRwKv/jXUvPiSk12pI3LeeaSyz
YbGr8fOrLfVRQLPKnT0jHD/Jzns+nZT48QDYWO3CGWV7M2xi/FZA8t5I0JqE0nq6
qZb1AdGtsNJVOKd/brKufZtz4gw1MtyVoHKBtfJQ231iaUkJlULMoXkdmvK0j+2F
Y0qMAYDF3rfMMENrUpLt9ptzTeSMgwDX/uQch1oH0BYp40jqaTHzTmueNrXfvU+E
/VhcGdpik2wHW94NfXEH5hp+54AI3wEQ8F3e4U86ZeI0Flt11Cz+yrG/7A0PjHqY
OAMM+8xw+XONUalCCur/u3GfKPMBqvk=
-----END CERTIFICATE-----`

		path := filepath.Join(t.TempDir(), "valid.pem")
		if err := os.WriteFile(path, []byte(validPEM), 0644); err != nil {
			t.Fatalf("failed to create valid pem file: %v", err)
		}

		client, err := googleHTTPClientWithRoots(path)
		if err != nil {
			t.Fatalf("googleHTTPClientWithRoots() failed for valid pem: %v", err)
		}

		// Verify the underlying transport has TLS config set
		transport, ok := client.Transport.(*http.Transport)
		if !ok {
			t.Fatalf("client.Transport is not *http.Transport")
		}
		if transport.TLSClientConfig == nil {
			t.Fatalf("transport.TLSClientConfig is nil")
		}
		if transport.TLSClientConfig.RootCAs == nil {
			t.Fatalf("transport.TLSClientConfig.RootCAs is nil")
		}
	})
}
