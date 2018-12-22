package tpm2tools

import (
	"bytes"
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

	pubEncoded, err := ek.pubArea.Encode()
	if err != nil {
		t.Fatal(err)
	}

	hashFn, err := ek.pubArea.NameAlg.HashConstructor()
	if err != nil {
		t.Fatal(err)
	}
	hash := hashFn()

	hash.Write(pubEncoded)
	if !bytes.Equal(hash.Sum(nil), ek.Name().Value) {
		t.Fatal("Returned name and computed name do not match")
	}
}
