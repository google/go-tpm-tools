package models

import "time"

type FakeTimer struct {
	OutChan   chan time.Time
	ResetChan chan int
	StopChan  chan int
}

func NewFakeTimer() *FakeTimer {
	return &FakeTimer{
		OutChan:   make(chan time.Time, 1),
		ResetChan: make(chan int, 1),
		StopChan:  make(chan int, 1),
	}
}

func (f *FakeTimer) C() <-chan time.Time {
	return f.OutChan
}

func (f *FakeTimer) Reset(d time.Duration) bool {
	f.ResetChan <- 1
	return true
}

func (f *FakeTimer) Stop() bool {
	f.StopChan <- 1
	return true
}
