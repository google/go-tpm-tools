package models

import "time"

// Timer is an interface that wraps the basic methods of time.Timer.
type Timer interface {
	C() <-chan time.Time
	Stop() bool
	Reset(time.Duration) bool
}

// RealTimer is an implementation of Timer that uses a real time.Timer
type RealTimer struct {
	inner time.Timer
}

func NewRealTimer() *RealTimer {
	return &RealTimer{
		inner: *time.NewTimer(0),
	}
}

func (t *RealTimer) C() <-chan time.Time {
	return t.inner.C
}

func (t *RealTimer) Stop() bool {
	return t.inner.Stop()
}

func (t *RealTimer) Reset(d time.Duration) bool {
	return t.inner.Reset(d)
}
