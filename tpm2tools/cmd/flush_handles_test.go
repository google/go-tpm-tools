package main

import (
	"testing"

	"github.com/samdamana/go-tpm-tools/simulator"
	"github.com/samdamana/go-tpm/tpm2"
)

func TestFlushActiveHandles(t *testing.T) {
	simulator, err := simulator.Get()
	if err != nil {
		t.Fatal(err)
	}
	defer simulator.Close()

	// Loads then flushes 1, 2, ...maxHandles handles.
	for i := 0; i <= maxHandles; i++ {
		for j := 0; j < i; j++ {
			loadRandomExternalKey(t, simulator)
		}
		err = FlushActiveHandles(simulator)
		if err != nil {
			t.Fatal(err)
		}
	}

	// Ensure there are no active handles after all that.
	h, err := Handles(simulator, tpm2.HandleTypeTransient)
	if err != nil {
		t.Fatal(err)
	}
	if len(h) != 0 {
		t.Fatal("Bah this should be empty!")
	}
}
