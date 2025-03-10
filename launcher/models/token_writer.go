package models

import (
	"fmt"
	"os"
	"path"
)

const (
	tokenFileTmp = ".token.tmp"
)

// TokenWriter is an interface for writing the token to some destination.
type DataWriter interface {
	Write(token []byte) error
}

// FileWriter is a tokenWriter that writes the token to a file.
type FileWriter struct {
	directory string
	filename  string
}

// Write writes the data to a tmp file before copying it over to the desired location.
func (t *FileWriter) Write(token []byte) error {
	// Write to a temp file first.
	tmpTokenPath := path.Join(t.directory, tokenFileTmp)
	if err := os.WriteFile(tmpTokenPath, token, 0644); err != nil {
		return fmt.Errorf("failed to write a tmp token file: %v", err)
	}

	// Rename the temp file to the token file (to avoid race conditions).
	if err := os.Rename(tmpTokenPath, path.Join(t.directory, t.filename)); err != nil {
		return fmt.Errorf("failed to rename the token file: %v", err)
	}
	return nil
}

// NewFileWriter creates a FileWriter and ensures the directory exists.
func NewFileWriter(directory string, filename string) (*FileWriter, error) {
	if err := os.MkdirAll(directory, 0744); err != nil {
		return nil, err
	}
	return &FileWriter{directory: directory, filename: filename}, nil
}
