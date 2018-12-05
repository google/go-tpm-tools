package simulator

import (
	"testing"

	"github.com/google/go-tpm/tpm2"
)

func getSimulator(t *testing.T) *Simulator {
	simulator, err := Get()
	if err != nil {
		t.Fatal(err)
	}
	return simulator
}

func TestReset(t *testing.T) {
	s := getSimulator(t)
	defer s.Close()
	if err := s.Reset(); err != nil {
		t.Fatal(err)
	}
}
func TestManufactureReset(t *testing.T) {
	s := getSimulator(t)
	defer s.Close()
	if err := s.ManufactureReset(); err != nil {
		t.Fatal(err)
	}
}

func TestGetRandom(t *testing.T) {
	s := getSimulator(t)
	defer s.Close()
	result, err := tpm2.GetRandom(s, 10)
	if err != nil {
		t.Fatalf("GetRandom: %v", err)
	}
	t.Log(result)
}
