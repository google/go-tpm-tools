// Package main provides a test workload for cleanup.
package main

import (
	"flag"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"
)

var serverAddr = flag.String("server-addr", "", "UDP log server address in IP:port format (required)")

func main() {
	flag.Parse()

	// Create a buffered channel to receive signals early.
	sigs := make(chan os.Signal, 1)
	done := make(chan bool, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	// Validate server address (IP:PORT).
	if *serverAddr == "" {
		log.Fatal("-server-addr flag is required")
	}
	host, _, err := net.SplitHostPort(*serverAddr)
	if err != nil {
		log.Fatalf("invalid -server-addr format: %v", err)
	}
	if net.ParseIP(host) == nil {
		log.Fatal("-server-addr must contain a valid IP address")
	}

	// Send log messages to a server if it exists.
	conn, err := net.Dial("udp", *serverAddr)
	if err != nil {
		log.Printf("Could not connect to log server %s: %v. Logging to stderr.", *serverAddr, err)
	} else {
		// Use io.MultiWriter to send logs to the server AND print them to standard error
		log.SetOutput(io.MultiWriter(os.Stderr, conn))
		defer conn.Close()
		log.Println("Connected to log server.")
	}

	// Start a goroutine to wait for the signal and handle the shutdown logic.
	go func() {
		sig := <-sigs // Block until a signal is received.
		log.Printf("Workload received signal: %v\n", sig)

		// Perform cleanup operations here (e.g., close database connections,
		// stop servers, flush logs, etc.).
		log.Println("Workload performing cleanup for 10 seconds. Check the next message about the graceful exit")
		time.Sleep(10 * time.Second)

		done <- true // Signal that cleanup is complete.
	}()

	// Block the main goroutine until the 'done' channel receives a value.
	log.Println("Workload awaits signal.")

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	cnt := 0
	for {
		select {
		case <-ticker.C:
			log.Printf("Workload heartbeat (%d)\n", cnt)
			cnt++
		case <-done:
			log.Println("Workload exiting gracefully.")
			return
		}
	}
}
