// Package clock contains time-related utilities
package clock

import "time"

// Timer is an interface that wraps the basic methods of time.Timer.
type Timer interface {
	C() <-chan time.Time
	Stop() bool
	Reset(time.Duration) bool
}

// Ensure conformance on Timer
var _ Timer = (*RealTimer)(nil)

// RealTimer is an implementation of Timer that uses a real time.Timer.
type RealTimer struct {
	inner *time.Timer
}

// NewRealTimer creates and returns a reference to a RealTimer.
func NewRealTimer(d time.Duration) Timer {
	return &RealTimer{
		inner: time.NewTimer(d),
	}
}

// C returns the channel on which the timer will send the current time when it fires.
func (t *RealTimer) C() <-chan time.Time {
	return t.inner.C
}

// Stop stops the timer and returns true if the timer was active.
func (t *RealTimer) Stop() bool {
	return t.inner.Stop()
}

// Reset resets the timer to the specified duration and returns true if the timer was active.
func (t *RealTimer) Reset(d time.Duration) bool {
	return t.inner.Reset(d)
}
