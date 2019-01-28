package main

import (
	"testing"

	"github.com/google/go-tpm-tools/simulator"
	"github.com/samdamana/go-tpm-tools/tpm2tools"
	"github.com/samdamana/go-tpm-tools/tpm2tools/tpm2toolstest"
	"github.com/samdamana/go-tpm/tpm2"
)

const (
	// How many handles we will create within the simulator. This also appears
	// to be the maximum number of key entries before errors.
	maxHandles = 3
)

func TestHandleTypesFromFlags(t *testing.T) {
	for _, test := range []struct {
		flushTransientFlag     bool
		flushLoadedSessionFlag bool
		flushSavedSessionFlag  bool
		flushAllTypesFlag      bool
		want                   []tpm2.HandleType
	}{
		{false, false, false, false, []tpm2.HandleType{}},
		{true, false, false, false, []tpm2.HandleType{tpm2.HandleTypeTransient}},
		{false, true, false, false, []tpm2.HandleType{tpm2.HandleTypeLoadedSession}},
		{false, false, true, false, []tpm2.HandleType{tpm2.HandleTypeSavedSession}},
		{false, true, true, false, []tpm2.HandleType{tpm2.HandleTypeLoadedSession, tpm2.HandleTypeSavedSession}},
		{true, true, false, false, []tpm2.HandleType{tpm2.HandleTypeTransient, tpm2.HandleTypeLoadedSession}},
		{true, false, true, false, []tpm2.HandleType{tpm2.HandleTypeTransient, tpm2.HandleTypeSavedSession}},
		{true, true, true, false, []tpm2.HandleType{tpm2.HandleTypeTransient, tpm2.HandleTypeLoadedSession, tpm2.HandleTypeSavedSession}},
		{false, false, false, true, []tpm2.HandleType{tpm2.HandleTypeTransient, tpm2.HandleTypeLoadedSession, tpm2.HandleTypeSavedSession}},
	} {
		// Overwrite flag pointer values.
		flushTransient = &test.flushTransientFlag
		flushLoadedSession = &test.flushLoadedSessionFlag
		flushSavedSession = &test.flushSavedSessionFlag
		flushAllTypes = &test.flushAllTypesFlag

		got := handleTypesFromFlags()
		if len(got) != len(test.want) {
			t.Fatalf("got length (%d) not equal to want length (%d). got: %v; want: %v", len(got), len(test.want), got, test.want)
		}
		for i, v := range got {
			if v != test.want[i] {
				t.Fatalf("got %v; want %v;", got, test.want)
			}
		}
	}
}

func TestFlushHandlesOfType(t *testing.T) {
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
		err = flushHandlesOfType(simulator, tpm2.HandleTypeTransient)
		if err != nil {
			t.Fatal(err)
		}
	}

	// Ensure there are no active handles after all that.
	h, err := tpm2tools.Handles(simulator, tpm2.HandleTypeTransient)
	if err != nil {
		t.Fatal(err)
	}
	if len(h) != 0 {
		t.Fatal("Simulator should be empty of transient handles.")
	}
}
