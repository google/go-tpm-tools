package cmd

import "testing"

func execute(tb testing.TB, args []string, opts ...envOption) error {
	tb.Helper()
	root := newRootCmd(opts...)
	root.SetArgs(args)
	return root.Execute()
}
