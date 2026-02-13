//go:build linux

package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	socketPath string
)

func init() {
	rootCmd.PersistentFlags().StringVar(&socketPath, "socket", "/tmp/teeserver.sock", "Path to the UNIX socket")
}

var rootCmd = &cobra.Command{
	Use:   "teeserver",
	Short: "Standalone TEE server and client",
	Long:  `A standalone binary to run a TEE server or query its endpoints.`,
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
