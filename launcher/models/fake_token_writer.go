package models

import "errors"

type FakeTokenWriter struct {
	tokensReturned int
	tokens         [][]byte
	writeTokenFunc func([]byte) error
}

func NewFakeTokenWriter() *FakeTokenWriter {
	return &FakeTokenWriter{
		tokensReturned: 0,
		tokens:         make([][]byte, 0),
		writeTokenFunc: nil,
	}
}

func (f *FakeTokenWriter) Write(data []byte) error {
	if f.writeTokenFunc != nil {
		return f.writeTokenFunc(data)
	}

	f.tokens = append(f.tokens, data)
	return nil
}

func (f *FakeTokenWriter) GetNextToken() ([]byte, error) {
	if f.tokensReturned >= len(f.tokens) {
		return nil, errors.New("no new token added")
	}

	f.tokensReturned++
	return f.tokens[f.tokensReturned-1], nil
}
