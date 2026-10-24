package cmd

import (
	"context"
	"testing"
)

// execute runs args against a new command tree configured with opts.
func execute(tb testing.TB, args []string, opts ...envOption) error {
	tb.Helper()
	root := newRootCmd(opts...)
	root.SetArgs(args)
	return root.ExecuteContext(context.Background())
}
