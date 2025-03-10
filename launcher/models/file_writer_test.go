package models

import (
	"bytes"
	"os"
	"path"
	"testing"

	"github.com/google/go-tpm-tools/launcher/launcherfile"
)

func TestFileWriterWritesToDisk(t *testing.T) {
	// Do not create the directory

	directory := launcherfile.HostTmpPath
	filename := "token"
	tokenWriter, err := NewFileWriter(directory, filename)
	if err != nil {
		t.Fatalf("failed to create token writer: %v", err)
	}
	tokenWriter.Write([]byte("test token"))

	data, err := os.ReadFile(path.Join(directory, filename))
	if err != nil {
		t.Fatalf("failed to read token file: %v", err)
	}

	if !bytes.Equal(data, []byte("test token")) {
		t.Errorf("token written to file does not match expected token: got %v, want %v", data, "test token")
	}
}
