package tpm2tools

import (
	"testing"

	"github.com/google/go-tpm-tools/simulator"
)

func getEK(t *testing.T) (*simulator.Simulator, *Key) {
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
