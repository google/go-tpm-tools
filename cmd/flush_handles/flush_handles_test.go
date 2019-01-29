package main

import (
	"flag"
	"reflect"
	"testing"

	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm-tools/tpm2tools"
	"github.com/google/go-tpm-tools/tpm2tools/tpm2toolstest"
	"github.com/google/go-tpm/tpm2"
)

const (
	// Maximum number of handles to keys tests can create within a simulator.
	maxHandles = 3
)

func TestHandleTypesFromFlags(t *testing.T) {
	for _, test := range []struct {
		flushTransientFlag     string
		flushLoadedSessionFlag string
		flushSavedSessionFlag  string
		flushAllTypesFlag      string
		want                   []tpm2.HandleType
	}{
		{"f", "f", "f", "f", []tpm2.HandleType{}},
		{"t", "f", "f", "f", []tpm2.HandleType{tpm2.HandleTypeTransient}},
		{"f", "t", "f", "f", []tpm2.HandleType{tpm2.HandleTypeLoadedSession}},
		{"f", "f", "t", "f", []tpm2.HandleType{tpm2.HandleTypeSavedSession}},
		{"f", "t", "t", "f", []tpm2.HandleType{tpm2.HandleTypeLoadedSession, tpm2.HandleTypeSavedSession}},
		{"t", "t", "f", "f", []tpm2.HandleType{tpm2.HandleTypeTransient, tpm2.HandleTypeLoadedSession}},
		{"t", "f", "t", "f", []tpm2.HandleType{tpm2.HandleTypeTransient, tpm2.HandleTypeSavedSession}},
		{"t", "t", "t", "f", []tpm2.HandleType{tpm2.HandleTypeTransient, tpm2.HandleTypeLoadedSession, tpm2.HandleTypeSavedSession}},
		{"f", "f", "f", "t", []tpm2.HandleType{tpm2.HandleTypeTransient, tpm2.HandleTypeLoadedSession, tpm2.HandleTypeSavedSession}},
	} {
		// Overwrite flag pointer values.
		flag.Set("flush-transient", test.flushTransientFlag)
		flag.Set("flush-loaded-session", test.flushLoadedSessionFlag)
		flag.Set("flush-saved-session", test.flushSavedSessionFlag)
		flag.Set("flush-all-types", test.flushAllTypesFlag)

		got := handleTypesFromFlags()
		if !reflect.DeepEqual(got, test.want) {
			t.Fatalf("got %v; want %v;", got, test.want)
		}
	}
}

func TestFlush(t *testing.T) {
	simulator, err := simulator.Get()
	if err != nil {
		t.Fatal(err)
	}
	defer simulator.Close()

	// Loads then flushes 1, 2, ...maxHandles transient handles.
	for i := 0; i <= maxHandles; i++ {
		for j := 0; j < i; j++ {
			tpm2toolstest.LoadRandomExternalKey(t, simulator)
		}
		if err = flush(simulator, tpm2.HandleTypeTransient); err != nil {
			t.Fatal(err)
		}
	}

	// Ensure there are no active handles after all that.
	h, err := tpm2tools.Handles(simulator, tpm2.HandleTypeTransient)
	if err != nil {
		t.Fatal(err)
	}
	if len(h) != 0 {
		t.Fatalf("Simulator should be empty of transient handles; got: %d", len(h))
	}
}
