// investigator is the investigator service.
package main

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
)

const (
	ListenPort = ":2080"
	TargetLog  = "10.138.0.10:2020"
)

func main() {
	// Listen for UDP commands on port 2080
	addr, _ := net.ResolveUDPAddr("udp", ListenPort)
	conn, _ := net.ListenUDP("udp", addr)
	defer conn.Close()

	// Dial the log server
	targetAddr, _ := net.ResolveUDPAddr("udp", TargetLog)
	targetConn, _ := net.DialUDP("udp", nil, targetAddr)
	defer targetConn.Close()

	// Send early-boot safe startup message (no race conditions!)
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown-host"
	}
	startupMsg := fmt.Sprintf("--- Go Investigator started on %s ---\n", hostname)
	targetConn.Write([]byte(startupMsg))

	buf := make([]byte, 2048)
	for {
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			continue
		}
		cmdStr := strings.TrimSpace(string(buf[:n]))
		if cmdStr == "" {
			continue
		}

		// Execute the command inside the host shell
		out, err := exec.Command("sh", "-c", cmdStr).CombinedOutput()
		if err != nil {
			targetConn.Write([]byte("Error: " + err.Error() + "\n" + string(out)))
		} else {
			targetConn.Write(out)
		}
	}
}
