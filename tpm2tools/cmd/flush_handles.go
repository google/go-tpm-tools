package main

import (
	"flag"
	"fmt"
	"io"
	"log"

	"github.com/samdamana/go-tpm-tools/tpm2tools"
	"github.com/samdamana/go-tpm/tpm2"
)

var (
	flushAllTypes = flag.Bool("flush-all-types", false, "Flush all handle types in addition to HandleTypeTransient.")
	tpmPath       = flag.String("tpm-path", "/dev/tpm0", "path to a TPM character device or socket")
	handleTypes   = []tpm2.HandleType{tpm2.HandleTypeTransient}
)

func main() {
	if *flushAllTypes {
		log.Println("Flushing handles of all types.") // TODO figure out if this is useful. Ask awly.
	} else {
		log.Println("Flushing all handles of type: [d]")
	}

	// rw, err := tpm2.OpenTPM(*tpmPath)
	// if err != nil {
	// 	log.Fatalf("%v", err)
	// }

	// for _, handleType := range handleTypes {
	// 	err = flushHandlesOfType(rw, handleType)
	// 	if err != nil {
	// 		log.Fatalf("%v", err)
	// 	}
	// }

	log.Println("Done!")
}

func flushHandlesOfType(rw io.ReadWriter, handleType tpm2.HandleType) error {
	handles, err := tpm2tools.Handles(rw, handleType)
	if err != nil {
		return fmt.Errorf("Error getting handles: %v", err)
	}
	for _, handle := range handles {
		err = tpm2.FlushContext(rw, handle)
		if err != nil {
			return fmt.Errorf("Error flushing handle(%v): %v", handle, err)
		}
	}
	return nil
}

// FlushActiveHandles calls FlushContext() on all active handles within the
// TPM at io.ReadWriter rw. Returns nil if successful or TPM has no active
// handles.
