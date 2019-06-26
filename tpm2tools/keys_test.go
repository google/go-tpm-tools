package tpm2tools

import (
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"

	"github.com/google/go-tpm-tools/internal"
)

func TestNameMatchesPublicArea(t *testing.T) {
	rwc := internal.GetTPM(t)
	defer CheckedClose(t, rwc)
	ek, err := EndorsementKeyRSA(rwc)
	if err != nil {
		t.Fatal(err)
	}
	defer ek.Close()

	matches, err := ek.Name().MatchesPublic(ek.pubArea)
	if err != nil {
		t.Fatal(err)
	}
	if !matches {
		t.Fatal("Returned name and computed name do not match")
	}
}

func TestCreateSigningKeysInHierarchies(t *testing.T) {
	rwc := internal.GetTPM(t)
	defer CheckedClose(t, rwc)
	template := AIKTemplateRSA([256]byte{})

	// We are not authorized to create keys in the Platform Hierarchy
	for _, hierarchy := range []tpmutil.Handle{tpm2.HandleOwner, tpm2.HandleEndorsement, tpm2.HandleNull} {
		key, err := NewKey(rwc, hierarchy, template)
		if err != nil {
			t.Errorf("Hierarchy %+v: %s", hierarchy, err)
		} else {
			key.Close()
		}
	}
}

func BenchmarkEndorsementKeyRSA(b *testing.B) {
	b.StopTimer()
	rwc := internal.GetTPM(b)
	defer CheckedClose(b, rwc)
	b.StartTimer()
	for n := 0; n < b.N; n++ {
		key, err := EndorsementKeyRSA(rwc)
		if err != nil {
			b.Fatal(err)
		}
		key.Close()
	}
}

func BenchmarkStorageRootKeyRSA(b *testing.B) {
	b.StopTimer()
	rwc := internal.GetTPM(b)
	defer CheckedClose(b, rwc)
	b.StartTimer()
	for n := 0; n < b.N; n++ {
		key, err := StorageRootKeyRSA(rwc)
		if err != nil {
			b.Fatal(err)
		}
		key.Close()
	}
}

func BenchmarkNullSigningKeyRSA(b *testing.B) {
	b.StopTimer()
	rwc := internal.GetTPM(b)
	defer CheckedClose(b, rwc)
	template := AIKTemplateRSA([256]byte{})
	b.StartTimer()
	for n := 0; n < b.N; n++ {
		key, err := NewKey(rwc, tpm2.HandleNull, template)
		if err != nil {
			b.Fatal(err)
		}
		key.Close()
	}
}
