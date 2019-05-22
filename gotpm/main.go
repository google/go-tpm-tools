package main

import (
	"os"

	"github.com/google/go-tpm-tools/gotpm/cmd"
)

func main() {
	if cmd.RootCmd.Execute() != nil {
		os.Exit(1)
	}
}
