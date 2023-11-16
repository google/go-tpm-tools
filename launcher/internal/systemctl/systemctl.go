// Package systemctl implements a subset of systemctl operations.
package systemctl

import (
	"fmt"
	"log"

	"github.com/coreos/go-systemd/dbus"
)

// Systemd is an interface to connect to host systemd with selected functions.
type Systemd interface {
	Start(string) error
	Stop(string) error
	Close()
}

// Systemctl is a wrap around of dbus.Conn and implements the Systemd interface.
type Systemctl struct {
	dbus *dbus.Conn
}

var _ Systemd = (*Systemctl)(nil)

// New connects to systemd over dbus.
func New() (*Systemctl, error) {
	conn, err := dbus.New()
	if err != nil {
		return nil, err
	}
	return &Systemctl{dbus: conn}, nil
}

// Start is the equivalent of `systemctl start $unit`.
func (s *Systemctl) Start(unit string) error {
	return runSystemdCmd(s.dbus.StartUnit, "start", unit)
}

// Stop is the equivalent of `systemctl stop $unit`.
func (s *Systemctl) Stop(unit string) error {
	return runSystemdCmd(s.dbus.StopUnit, "stop", unit)
}

// Close disconnects from dbus.
func (s *Systemctl) Close() { s.dbus.Close() }

func runSystemdCmd(cmdFunc func(string, string, chan<- string) (int, error), cmd string, unit string) error {
	progress := make(chan string, 1)

	// Run systemd command in "replace" mode to start the unit and its dependencies,
	// possibly replacing already queued jobs that conflict w∏ith this.
	if _, err := cmdFunc(unit, "replace", progress); err != nil {
		return fmt.Errorf("failed to run systemctl [%s] for unit [%s]: %v", cmd, unit, err)
	}

	if result := <-progress; result != "done" {
		return fmt.Errorf("systemctl [%s] result was [%s], want done", cmd, result)
	}

	log.Printf("Finished up systemctl [%s] for unit [%s]", cmd, unit)
	return nil
}
