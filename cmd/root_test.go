package cmd

import "io"

func testTPM(tpm io.ReadWriter) func(string) (io.ReadWriteCloser, error) {
	return func(string) (io.ReadWriteCloser, error) {
		return extTPMWrapper{tpm}, nil
	}
}

func execute(args []string, tpm io.ReadWriter) error {
	root := newRootCmd(testTPM(tpm))
	root.SetArgs(args)
	return root.Execute()
}
