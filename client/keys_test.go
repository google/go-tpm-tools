package client_test

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"io"
	"math/big"
	"reflect"
	"testing"
	"time"

	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"

	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm-tools/internal/test"
)

func TestNameMatchesPublicArea(t *testing.T) {
	rwc := test.GetTPM(t)
	defer client.CheckedClose(t, rwc)
	ek, err := client.EndorsementKeyRSA(rwc)
	if err != nil {
		t.Fatal(err)
	}
	defer ek.Close()

	matches, err := ek.Name().MatchesPublic(ek.PublicArea())
	if err != nil {
		t.Fatal(err)
	}
	if !matches {
		t.Fatal("Returned name and computed name do not match")
	}
}

func TestCreateSigningKeysInHierarchies(t *testing.T) {
	rwc := test.GetTPM(t)
	defer client.CheckedClose(t, rwc)
	template := client.AKTemplateRSA()

	// We are not authorized to create keys in the Platform Hierarchy
	for _, hierarchy := range []tpmutil.Handle{tpm2.HandleOwner, tpm2.HandleEndorsement, tpm2.HandleNull} {
		key, err := client.NewKey(rwc, hierarchy, template)
		if err != nil {
			t.Errorf("Hierarchy %+v: %s", hierarchy, err)
		} else {
			key.Close()
		}
	}
}

func TestCachedRSAKeys(t *testing.T) {
	rwc := test.GetTPM(t)
	defer client.CheckedClose(t, rwc)
	keys := []struct {
		name   string
		getKey func(io.ReadWriter) (*client.Key, error)
	}{
		{"SRK", client.StorageRootKeyRSA},
		{"EK", client.EndorsementKeyRSA},
	}

	for _, k := range keys {
		t.Run(k.name, func(t *testing.T) {
			// Get the key the first time and persist
			srk, err := k.getKey(rwc)
			if err != nil {
				t.Fatal(err)
			}
			defer srk.Close()

			pub := srk.PublicKey()
			if tpm2.FlushContext(rwc, srk.Handle()) == nil {
				t.Error("Trying to flush persistent keys should fail.")
			}

			// Get the cached key (should be the same)
			srk, err = k.getKey(rwc)
			if err != nil {
				t.Fatal(err)
			}
			defer srk.Close()

			if !reflect.DeepEqual(srk.PublicKey(), pub) {
				t.Errorf("Expected pub key: %v got: %v", pub, srk.PublicKey())
			}

			// We should still get the same key if we evict the handle
			if err := tpm2.EvictControl(rwc, "", tpm2.HandleOwner, srk.Handle(), srk.Handle()); err != nil {
				t.Errorf("Evicting control failed: %v", err)
			}
			srk, err = k.getKey(rwc)
			if err != nil {
				t.Fatal(err)
			}
			defer srk.Close()

			if !reflect.DeepEqual(srk.PublicKey(), pub) {
				t.Errorf("Expected pub key: %v got: %v", pub, srk.PublicKey())
			}
		})
	}
}

func TestKeyCreation(t *testing.T) {
	rwc := test.GetTPM(t)
	defer client.CheckedClose(t, rwc)

	keys := []struct {
		name   string
		getKey func(io.ReadWriter) (*client.Key, error)
	}{
		{"SRK-ECC", client.StorageRootKeyECC},
		{"EK-ECC", client.EndorsementKeyECC},
		{"AK-ECC", client.AttestationKeyECC},
		{"SRK-RSA", client.StorageRootKeyRSA},
		{"EK-RSA", client.EndorsementKeyRSA},
		{"AK-RSA", client.AttestationKeyRSA},
	}

	for _, k := range keys {
		t.Run(k.name, func(t *testing.T) {
			key, err := k.getKey(rwc)
			if err != nil {
				t.Fatal(err)
			}
			key.Close()
		})
	}
}

func BenchmarkKeyCreation(b *testing.B) {
	rwc := test.GetTPM(b)
	defer client.CheckedClose(b, rwc)

	benchmarks := []struct {
		name   string
		getKey func(io.ReadWriter) (*client.Key, error)
	}{
		{"SRK-ECC-Cached", client.StorageRootKeyECC},
		{"EK-ECC-Cached", client.EndorsementKeyECC},
		{"AK-ECC-Cached", client.AttestationKeyECC},

		{"SRK-ECC", func(rw io.ReadWriter) (*client.Key, error) {
			return client.NewKey(rw, tpm2.HandleOwner, client.SRKTemplateECC())
		}},
		{"EK-ECC", func(rw io.ReadWriter) (*client.Key, error) {
			return client.NewKey(rw, tpm2.HandleEndorsement, client.DefaultEKTemplateECC())
		}},
		{"AK-ECC", func(rw io.ReadWriter) (*client.Key, error) {
			return client.NewKey(rw, tpm2.HandleOwner, client.AKTemplateECC())
		}},

		{"SRK-RSA-Cached", client.StorageRootKeyRSA},
		{"EK-RSA-Cached", client.EndorsementKeyRSA},
		{"AK-RSA-Cached", client.AttestationKeyRSA},

		{"SRK-RSA", func(rw io.ReadWriter) (*client.Key, error) {
			return client.NewKey(rw, tpm2.HandleEndorsement, client.SRKTemplateRSA())
		}},
		{"EK-RSA", func(rw io.ReadWriter) (*client.Key, error) {
			return client.NewKey(rw, tpm2.HandleOwner, client.DefaultEKTemplateRSA())
		}},
		{"AK-RSA", func(rw io.ReadWriter) (*client.Key, error) {
			return client.NewKey(rw, tpm2.HandleOwner, client.AKTemplateRSA())
		}},
	}

	for _, bm := range benchmarks {
		b.Run(bm.name, func(b *testing.B) {
			// Don't count time to populate the cache
			b.StopTimer()
			key, err := bm.getKey(rwc)
			if err != nil {
				b.Fatal(err)
			}
			key.Close()
			b.StartTimer()

			for i := 0; i < b.N; i++ {
				key, err := bm.getKey(rwc)
				if err != nil {
					b.Fatal(err)
				}
				key.Close()
			}
		})
	}
}

// Returns an x509 Certificate for the provided pubkey, signed with the provided parent certificate and key.
// If the provided fields are nil, will create a self-signed certificate.
func getTestCert(t *testing.T, pubKey crypto.PublicKey, parentCert *x509.Certificate, parentKey *rsa.PrivateKey) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()

	certKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}

	if pubKey == nil && parentCert == nil && parentKey == nil {
		pubKey = certKey.Public()
		parentCert = template
		parentKey = certKey
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, template, parentCert, pubKey, parentKey)
	if err != nil {
		t.Fatalf("Unable to create test certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		t.Fatalf("Unable to parse test certificate: %v", err)
	}

	return cert, certKey
}

func TestSetCert(t *testing.T) {
	rwc := test.GetTPM(t)
	defer client.CheckedClose(t, rwc)

	key, err := client.AttestationKeyECC(rwc)
	if err != nil {
		t.Fatalf("Unable to create key: %v", err)
	}

	ca, caKey := getTestCert(t, nil, nil, nil)
	akCert, _ := getTestCert(t, key.PublicKey(), ca, caKey)

	if err = key.SetCert(akCert); err != nil {
		t.Errorf("SetCert() returned error: %v", err)
	}
}

func TestSetCertFailsIfCertificateIsNotForKey(t *testing.T) {
	rwc := test.GetTPM(t)
	defer client.CheckedClose(t, rwc)
	key, err := client.AttestationKeyECC(rwc)
	if err != nil {
		t.Fatalf("Unable to create key: %v", err)
	}

	otherKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	ca, caKey := getTestCert(t, nil, nil, nil)
	akCert, _ := getTestCert(t, otherKey.Public(), ca, caKey)

	if err = key.SetCert(akCert); err == nil {
		t.Error("SetCert() returned successfully, expected error")
	}
}

func TestLoadCachedKey(t *testing.T) {
	rwc := test.GetTPM(t)
	defer client.CheckedClose(t, rwc)

	createdKey, err := client.NewKey(rwc, tpm2.HandleNull, client.SRKTemplateRSA())
	if err != nil {
		t.Fatalf("NewKey() returned error: %v", err)
	}
	defer createdKey.Close()

	handles := []struct {
		name        string
		handle      tpmutil.Handle
		errExpected bool
	}{
		{"successful retrieval with handle", createdKey.Handle(), false},
		{"error for bad handle", tpmutil.Handle(0x0), true},
	}

	for _, k := range handles {
		t.Run(k.name, func(t *testing.T) {
			loadedKey, err := client.LoadCachedKey(rwc, createdKey.Handle(), client.NullSession{})
			if k.errExpected && err == nil {
				t.Fatal("LoadCachedKey() returned successfully, expected error")
			} else if !k.errExpected && err != nil {
				t.Fatalf("LoadCachedKey() returned error: %v", err)
			} else if k.errExpected {
				return
			}
			defer loadedKey.Close()

			if !reflect.DeepEqual(createdKey, loadedKey) {
				t.Errorf("Loaded key does not match created key")
			}
		})
	}
}
