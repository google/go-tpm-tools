package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"os"
	"path/filepath"
	"time"
	"unicode/utf8"
)

// readFileWithTimeout attempts a full read first, and if it times out, falls back to a partial read.
func readFileWithTimeout(path string, fullTimeout, partialTimeout time.Duration) (data []byte, isPartial bool, err error) {
	type result struct {
		data []byte
		err  error
	}

	// Stage 1: Full Read
	ch1 := make(chan result, 1)
	go func() {
		data, err := os.ReadFile(path)
		ch1 <- result{data, err}
	}()

	select {
	case res := <-ch1:
		return res.data, false, res.err
	case <-time.After(fullTimeout):
		// Full read timed out
	}

	// Stage 2: Partial Read
	ch2 := make(chan result, 1)
	go func() {
		f, err := os.Open(path)
		if err != nil {
			ch2 <- result{nil, err}
			return
		}
		defer f.Close()

		buf := make([]byte, 1024) // Read up to 1024 bytes
		n, err := f.Read(buf)
		if err != nil && err != io.EOF {
			ch2 <- result{nil, err}
			return
		}
		ch2 <- result{buf[:n], nil}
	}()

	select {
	case res := <-ch2:
		return res.data, true, res.err
	case <-time.After(partialTimeout):
		return nil, false, fmt.Errorf("timed out")
	}
}

func main() {
	outFlag := flag.String("out", "stdout", "Output destination: all, stdout, serial")
	flag.Parse()

	var writers []io.Writer

	// Network output is always included in all valid configurations based on requirements.
	// We attempt to connect to UDP 10.138.0.10:2020.
	conn, err := net.Dial("udp", "10.138.0.10:2020")
	if err != nil {
		log.Printf("Failed to connect to UDP: %v", err)
	} else {
		defer conn.Close()
		writers = append(writers, conn)
	}

	switch *outFlag {
	case "stdout":
		writers = append(writers, os.Stdout)
	case "serial":
		serialFile, err := os.OpenFile("/dev/ttyS0", os.O_WRONLY|os.O_APPEND, 0666)
		if err != nil {
			log.Printf("Failed to open serial port: %v", err)
		} else {
			defer serialFile.Close()
			writers = append(writers, serialFile)
		}
	case "all":
		writers = append(writers, os.Stdout)
		serialFile, err := os.OpenFile("/dev/ttyS0", os.O_WRONLY|os.O_APPEND, 0666)
		if err != nil {
			log.Printf("Failed to open serial port: %v", err)
		} else {
			defer serialFile.Close()
			writers = append(writers, serialFile)
		}
	default:
		log.Printf("Invalid --out value: %s. Defaulting to include stdout.", *outFlag)
		writers = append(writers, os.Stdout)
	}

	// Fallback to stdout if no writers are configured (e.g. if UDP failed and serial was requested but failed)
	if len(writers) == 0 {
		writers = append(writers, os.Stdout)
	}

	log.SetOutput(io.MultiWriter(writers...))
	log.SetFlags(0) // Remove date and time flags

	root := "/sys"
	log.Printf("Starting enumeration of %s", root)

	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			log.Printf("[ERROR] %s: %v", path, err)
			return nil // Continue walking
		}

		if d.IsDir() {
			return nil
		}

		// Try to read the file with fallback (2s for full read, 500ms for partial read)
		content, isPartial, readErr := readFileWithTimeout(path, 2*time.Second, 500*time.Millisecond)
		if readErr != nil {
			log.Printf("[UNREADABLE/TIMEOUT] %s: %v", path, readErr)
		} else {
			prefix := "[READABLE TEXT]"
			if isPartial {
				prefix = "[PARTIAL TEXT]"
			}

			if utf8.Valid(content) {
				log.Printf("%s %s: %s", prefix, path, string(content))
			} else {
				encoded := base64.StdEncoding.EncodeToString(content)
				if isPartial {
					prefix = "[PARTIAL BINARY]"
				} else {
					prefix = "[READABLE BINARY]"
				}
				log.Printf("%s %s: %s", prefix, path, encoded)
			}
		}

		return nil
	})

	if err != nil {
		log.Printf("WalkDir failed: %v", err)
	}
}
