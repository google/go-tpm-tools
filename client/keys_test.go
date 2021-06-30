package client_test

import (
	"io"
	"reflect"
	"testing"

	"github.com/google/go-tpm/tpm2"
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
