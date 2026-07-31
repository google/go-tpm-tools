// Package main is a simple test workload that requests an attestation token from the ITA endpoint.
package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
)

const (
	socketPath = "/run/container_launcher/teeserver.sock"
	url        = "http://localhost/v1/intel/token"
)

func main() {
	fmt.Println("ITA Test Workload running")
	httpClient := http.Client{
		Transport: &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", socketPath)
			},
		},
	}

	resp, err := httpClient.Get(url)
	if err != nil {
		fmt.Println("failed to get token:", err)
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("failed to read body:", err)
		return
	}

	fmt.Printf("Response: %s\n", body)
}
