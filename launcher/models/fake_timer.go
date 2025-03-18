package models

import "time"

// FakeTimer is a fake implementation of Timer for testing purposes.
type FakeTimer struct {
	OutChan   chan time.Time
	ResetChan chan int
	StopChan  chan int
}

// NewFakeTimer creates a new instance of FakeTimer.
func NewFakeTimer() *FakeTimer {
	return &FakeTimer{
		OutChan:   make(chan time.Time, 1),
		ResetChan: make(chan int, 1),
		StopChan:  make(chan int, 1),
	}
}

// C returns the channel on which the timer will send the current time when it fires.
func (f *FakeTimer) C() <-chan time.Time {
	return f.OutChan
}

// Reset notifies the reset channel to signal that that reset was called.
func (f *FakeTimer) Reset(_ time.Duration) bool {
	f.ResetChan <- 1
	return true
}

// Stop notifies the stop channel to signal that stop was called.
func (f *FakeTimer) Stop() bool {
	f.StopChan <- 1
	return true
}
