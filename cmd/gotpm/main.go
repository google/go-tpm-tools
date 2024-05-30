// Package main is a binary wrapper package around cmd.
package main

import (
	"fmt"
	"os"
	"runtime/debug"

	"github.com/google/go-tpm-tools/cmd"
)

// GoReleaser will populates those fields
// https://goreleaser.com/cookbooks/using-main.version/
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

var (
	tdxGuestVersion = "unknown"
	sevGuestVersion = "unknown"
	sevGuest        = "github.com/google/go-sev-guest"
	tdxGuest        = "github.com/google/go-tdx-guest"
)

func main() {
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, dep := range info.Deps {
			switch dep.Path {
			case sevGuest:
				sevGuestVersion = dep.Version
			case tdxGuest:
				tdxGuestVersion = dep.Version
			}
		}
	}

	cmd.RootCmd.Version = fmt.Sprintf("%s, commit %s, built at %s\n- go-sev-guest version %s\n- go-tdx-guest version %s",
		version, commit, date, tdxGuestVersion, sevGuestVersion)

	if cmd.RootCmd.Execute() != nil {
		os.Exit(1)
	}
}
