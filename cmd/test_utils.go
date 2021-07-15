package cmd

import (
	"io/ioutil"
	"testing"
)

func makeTempFile(tb testing.TB, content []byte) string {
	tb.Helper()
	file, err := ioutil.TempFile("", "gotpm_test_*.txt")
	if err != nil {
		tb.Fatal(err)
	}
	defer file.Close()
	if content != nil {
		if _, err := file.Write(content); err != nil {
			tb.Fatal(err)
		}
	}
	return file.Name()
}
