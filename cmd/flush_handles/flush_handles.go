package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/google/go-tpm-tools/tpm2tools"
	"github.com/google/go-tpm/tpm2"
)

var (
	tpmPath            = flag.String("tpm-path", "/dev/tpm0", "Path to a TPM character device or socket.")
	flushTransient     = flag.Bool("flush-transient", true, "Flush all transient handles.")
	flushLoadedSession = flag.Bool("flush-loaded-session", false, "Flush all loaded session handles.")
	flushSavedSession  = flag.Bool("flush-saved-session", false, "Flush all saved session handles.")
	flushAllTypes      = flag.Bool("flush-all-types", false, "Flush handles of all handle types. If enabled,\nsettings for other handle types are ignored.")
)

func main() {
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "%s - Flush active TPM handles from the device\n\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()

	handleTypes := handleTypesFromFlags()
	n, err := flushAll(handleTypes)
	if err != nil {
		log.Fatalf("%v", err)
	}
	fmt.Printf("%d handles successfully flushed\n", n)
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

// flushAll opens the TPM defined at the flag tpm-path
// and calls flushHandlesOfType on every type within handleTypes.
// On success, this function returns the total number of handles flushed.
func flushAll(handleTypes []tpm2.HandleType) (int, error) {
	rw, err := tpm2.OpenTPM(*tpmPath)
	if err != nil {
		return 0, err
	}
	defer rw.Close()

	total := 0
	for _, handleType := range handleTypes {
		count, err := flush(rw, handleType)
		if err != nil {
			return 0, err
		}
		total += count
	}
	return total, nil
}

// flush calls FlushContext() on all handles within the
// TPM at io.ReadWriter rw of tpm2.HandleType handleType.
// On success, this function returns the number of handles flushed.
func flush(rw io.ReadWriter, handleType tpm2.HandleType) (int, error) {
	handles, err := tpm2tools.Handles(rw, handleType)
	if err != nil {
		return 0, fmt.Errorf("Error getting handles: %v", err)
	}
	for _, handle := range handles {
		log.Printf("Flushing handle (type 0x%x): 0x%x", handleType, handle)
		if err = tpm2.FlushContext(rw, handle); err != nil {
			return 0, fmt.Errorf("Error flushing handle(%v): %v", handle, err)
		}
	}
	return len(handles), nil
}
