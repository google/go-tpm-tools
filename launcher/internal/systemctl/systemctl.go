// Package systemctl implements some systemctl operations.
package systemctl

import (
	"context"
	"fmt"
	"log"
	"sync"
	"github.com/coreos/go-systemd/dbus"
)

// Systemd is used to talk to systemd.
type Systemd interface {
	Start(ctx context.Context, unit string) error
	Stop(ctx context.Context, unit string) error
	TryRestart(ctx context.Context, unit string) error
	Restart(ctx context.Context, unit string) error
	GetStatus(ctx context.Context, unit string) (string, error)
	Close() error
	GetProperty(ctx context.Context, unit, property string) (*dbus.Property, error)
	Enable(files []string, runtime bool) (bool, []dbus.EnableUnitFileChange, error)
	Unmask(files []string, runtime bool) ([]dbus.UnmaskUnitFileChange, error)
}

// NewDbus connects to systemd over dbus.
func NewDbus() (Systemd, error) {
	conn, err := dbus.New()
	if err != nil {
		return nil, err
	}
	return &dbusSystemd{dbus: conn, jobMap: make(map[string]([]chan string))}, nil
}

type dbusSystemd struct {
	dbus   *dbus.Conn
	mu     sync.Mutex
	jobMap map[string]([]chan string)
}

var _ Systemd = &dbusSystemd{}

// Start is the equivalent of `systemctl start $unit`.
func (ds *dbusSystemd) Start(ctx context.Context, unit string) error {
	return ds.RunCmd(ctx, ds.dbus.StartUnit, "start", unit)
}

func (ds *dbusSystemd) Enable(files []string, runtime bool) (bool, []dbus.EnableUnitFileChange, error) {
	return ds.dbus.EnableUnitFiles(files, runtime, runtime)
}

func (ds *dbusSystemd) Unmask(files[] string, runtime bool) ([]dbus.UnmaskUnitFileChange, error) {
	return ds.dbus.UnmaskUnitFiles(files, runtime)
}

// Stop is the equivalent of `systemctl stop $unit`.
func (ds *dbusSystemd) Stop(ctx context.Context, unit string) error {
	return ds.RunCmd(ctx, ds.dbus.StopUnit, "stop", unit)
}

// TryRestart is the equivalent of `systemctl try-restart $unit`.
func (ds *dbusSystemd) TryRestart(ctx context.Context, unit string) error {
	return ds.RunCmd(ctx, ds.dbus.TryRestartUnit, "tryRestart", unit)
}

// Restart is the equivalent of `systemctl restart $unit`.
func (ds *dbusSystemd) Restart(ctx context.Context, unit string) error {
	return ds.RunCmd(ctx, ds.dbus.RestartUnit, "restart", unit)
}

// GetStatus gets the status string for a unit.
// Can be "active", "activating", "deactivating", "inactive" or "failed".
func (ds *dbusSystemd) GetStatus(ctx context.Context, unit string) (string, error) {
	log.Printf("GetStatus for systemd unit %q", unit)
	status, err := ds.dbus.ListUnitsByNames([]string{unit})
	if err != nil {
		return "", err
	}
	if len(status) != 1 {
		return "", fmt.Errorf("expected 1 unit from ListUnitsByNames, got %d", len(status))
	}
	return status[0].ActiveState, nil
}

// GetProperty is the equivalent of `systemctl show $unit --property=$property`.
func (ds *dbusSystemd) GetProperty(ctx context.Context, unit, property string) (*dbus.Property, error) {
	return ds.dbus.GetUnitProperty(unit, property)
}

// Close disconnects from dbus.
func (ds *dbusSystemd) Close() error {
	ds.dbus.Close()
	return nil
}

// RunCmd runs a systemctl command for a systemd unit
func (ds *dbusSystemd) RunCmd(ctx context.Context, cmdUnitFunc func(string, string, chan<- string) (int, error), cmd string, unit string) error {
	progress := make(chan string, 10)

	// When the same cmd+unit runs at the same time, the dbus library may return the same job.
	// But the dbus library has a bug that in this case, it returns done to only one progress channel,
	// that leaves other jobs blocking at waiting for progress.
	// To get around the problem, we record all channels belonging to the same task, and send result
	// after one of the channels receives result.
	ds.mu.Lock()
	job, err := cmdUnitFunc(unit, "replace", progress)
	if err != nil {
		ds.mu.Unlock()
		return fmt.Errorf("%q %q failure: %v", cmd, unit, err)
	}
	// Job id should be enough. For safety use cmd+unit+job.
	mapKey := fmt.Sprintf("%v.%v.%v", cmd, unit, job)
	ds.jobMap[mapKey] = append(ds.jobMap[mapKey], progress)
	ds.mu.Unlock()

	log.Printf("%q %q jobid: %d", cmd, unit, job)
	// Wait for the job to finish.
	r := <-progress

	// Populate the result to other channels with the same job id.
	ds.mu.Lock()
	jobChs, ok := ds.jobMap[mapKey]
	if ok {
		delete(ds.jobMap, mapKey)
	}
	ds.mu.Unlock()

	for _, ch := range jobChs {
		ch <- r
	}

	if r != "done" {
		return fmt.Errorf(`%q %q status was %q, want "done"`, cmd, unit, r)
	}
	// Successful.
	log.Printf(`%q %q status (jobid %d) was "done"`, cmd, unit, job)

	return nil
}