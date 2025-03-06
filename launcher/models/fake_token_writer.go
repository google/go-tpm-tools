package models

import (
	"errors"
	"sync"
)

// FakeTokenWriter is a fake implementation of TokenWriter for testing purposes.
type FakeTokenWriter struct {
	tokensReturned int
	tokens         [][]byte
	writeTokenFunc func([]byte) error
	mu             *sync.Mutex
}

// NewFakeTokenWriter creates a new instance of FakeTokenWriter.
func NewFakeTokenWriter() *FakeTokenWriter {
	return &FakeTokenWriter{
		tokensReturned: 0,
		tokens:         make([][]byte, 0),
		writeTokenFunc: nil,
		mu:             &sync.Mutex{},
	}
}

// Write calls writeTokenFunc to write the token if it is set, otherwise appends the token to the tokens slice.
func (f *FakeTokenWriter) Write(data []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.writeTokenFunc != nil {
		return f.writeTokenFunc(data)
	}

	f.tokens = append(f.tokens, data)
	return nil
}

// GetNextToken returns the next token from the tokens slice.
// It returns an error if there are no more tokens to return.
func (f *FakeTokenWriter) GetNextToken() ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.tokensReturned >= len(f.tokens) {
		return nil, errors.New("no new token added")
	}

	f.tokensReturned++
	return f.tokens[f.tokensReturned-1], nil
}
