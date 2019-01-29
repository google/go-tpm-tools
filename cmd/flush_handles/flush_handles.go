package main

import (
	"flag"
	"fmt"
	"io"
	"log"

	"github.com/google/go-tpm-tools/tpm2tools"
	"github.com/google/go-tpm/tpm2"
)

var (
	tpmPath            = flag.String("tpm-path", "/dev/tpm0", "Path to a TPM character device or socket.")
	flushTransient     = flag.Bool("flush-transient", true, "Flush all transient handles.")
	flushLoadedSession = flag.Bool("flush-loaded-session", false, "Flush all loaded session handles.")
	flushSavedSession  = flag.Bool("flush-saved-session", false, "Flush all saved session handles.")
	flushAllTypes      = flag.Bool("flush-all-types", false, "Flush handles of all handle types. If enabled, settings for other handle types are ignored.")
)

func main() {
	flag.Parse()
	handleTypes := handleTypesFromFlags()
	err := openTPMAndFlushHandlesOfTypes(handleTypes)
	if err != nil {
		log.Fatalf("%v", err)
	}
	log.Println("Handles flushed!")
}

// handleTypeFromFlags parses flag values and returns a slice of
// tpm2.HandleType enums which should be flushed from the TPM.
func handleTypesFromFlags() []tpm2.HandleType {
	if *flushAllTypes {
		return []tpm2.HandleType{tpm2.HandleTypeTransient, tpm2.HandleTypeLoadedSession, tpm2.HandleTypeSavedSession}
	}
	types := []tpm2.HandleType{}
	if *flushTransient {
		types = append(types, tpm2.HandleTypeTransient)
	}
	if *flushLoadedSession {
		types = append(types, tpm2.HandleTypeLoadedSession)
	}
	if *flushSavedSession {
		types = append(types, tpm2.HandleTypeSavedSession)
	}
	return types
}

// openTPMAndFlushHandlesOfTypes opens the TPM defined at the flag tpm-path
// and calls flushHandlesOfType on every type within handleTypes.
func openTPMAndFlushHandlesOfTypes(handleTypes []tpm2.HandleType) error {
	rw, err := tpm2.OpenTPM(*tpmPath)
	if err != nil {
		return err
	}
	defer rw.Close()

	for _, handleType := range handleTypes {
		if err = flushHandlesOfType(rw, handleType); err != nil {
			return err
		}
	}
	return nil
}

// flushHandlesOfType calls FlushContext() on all handles within the
// TPM at io.ReadWriter rw of tpm2.HandleType handleType. Returns nil if
// successful or TPM has no active handles.
func flushHandlesOfType(rw io.ReadWriter, handleType tpm2.HandleType) error {
	handles, err := tpm2tools.Handles(rw, handleType)
	if err != nil {
		return fmt.Errorf("Error getting handles: %v", err)
	}
	for _, handle := range handles {
		log.Printf("Flushing handle (type 0x%x): 0x%x", handleType, handle)
		if err = tpm2.FlushContext(rw, handle); err != nil {
			return fmt.Errorf("Error flushing handle(%v): %v", handle, err)
		}
	}
	return nil
}
