package tpm2tools

import (
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"

	"github.com/google/go-tpm-tools/simulator"
)

func getEK(t *testing.T) (*simulator.Simulator, *Key) {
	t.Helper()
	simulator, err := simulator.Get()
	if err != nil {
		t.Fatal(err)
	}
	key, err := EndorsementKeyRSA(simulator)
	if err != nil {
		simulator.Close()
		t.Fatal(err)
	}
	return simulator, key
}

func TestNameMatchesPublicArea(t *testing.T) {
	s, ek := getEK(t)
	defer s.Close()
	defer ek.Close()

	matches, err := ek.Name().MatchesPublic(ek.pubArea)
	if err != nil {
		t.Fatal(err)
	}
	if !matches {
		t.Fatal("Returned name and computed name do not match")
	}
}

func TestCreateSigningKeysInAllHierarchies(t *testing.T) {
	simulator, err := simulator.Get()
	if err != nil {
		t.Fatal(err)
	}

	template := AIKTemplateRSA([256]byte{})
	for _, hierarchy := range []tpmutil.Handle{tpm2.HandleOwner, tpm2.HandleEndorsement, tpm2.HandlePlatform, tpm2.HandleNull} {
		key, err := NewKey(simulator, hierarchy, template)
		if err != nil {
			t.Errorf("Hierarchy %+v: %s", hierarchy, err)
		} else {
			key.Close()
		}
	}
}
