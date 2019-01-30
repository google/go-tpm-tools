package tpm2tools

import (
	"io"
	"testing"

	"github.com/google/go-tpm-tools/internal"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

// checkedClose closes the simluator and asserts that there were no leaked handles.
func checkedClose(tb testing.TB, rwc io.ReadWriteCloser) {
	types := []tpm2.HandleType{
		tpm2.HandleTypeLoadedSession,
		tpm2.HandleTypeSavedSession
		tpm2.HandleTypeTransient,
	}
	handles := []tpmutil.Handle{}
	for _, t := range types {
		h, err := Handles(rwc, t)
		if err != nil {
			tb.Fatalf("failed to fetch handles of type %v: %v", t, err)
		}
		handles = append(handles, h...)
	}

	err := rwc.Close()
	if err != nil {
		tb.Fatalf("failed to close simulator: %v", err)
	}

	if len(handles) != 0 {
		tb.Fatalf("tests leaked handles: %v", handles)
	}
}

func TestNameMatchesPublicArea(t *testing.T) {
	rwc := internal.GetTPM(t)
	defer checkedClose(t, rwc)
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
	defer checkedClose(t, rwc)
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
	defer rwc.Close()
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
	defer rwc.Close()
	b.StartTimer()
	for n := 0; n < b.N; n++ {
		key, err := StorageRootKeyRSA(rwc)
		if err != nil {
			b.Fatal(err)
		}
		key.Close()
	}
}
