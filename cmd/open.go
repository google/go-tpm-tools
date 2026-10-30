package cmd

import (
	"fmt"
	"io"
)

func (o *gotpmOptions) openTPM() (io.ReadWriteCloser, error) {
	rwc, err := o.tpmOpener(o.tpmPath)
	if err != nil {
		return nil, fmt.Errorf("connecting to TPM: %w", err)
	}
	return rwc, nil
}
