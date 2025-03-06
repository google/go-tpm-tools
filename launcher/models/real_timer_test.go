package models

import (
	"fmt"
	"testing"
	"time"
)

// This test relies on the timeout to fail, since channels will block indefinitely.
func TestRealTimerFires(_ *testing.T) {
	timer := NewRealTimer(100 * time.Millisecond)
	time.Sleep(125 * time.Millisecond)
	<-timer.C()

	fmt.Printf("%v\n", timer.Reset(100*time.Millisecond))
	time.Sleep(125 * time.Millisecond)
	<-timer.C()
}

// This test relies on the timeout to fail, since channels will block indefinitely.
func TestRealTimerFiresInstantly(_ *testing.T) {
	timer := NewRealTimer(0)
	<-timer.C()

	timer.Reset(100 * time.Millisecond)
	time.Sleep(125 * time.Millisecond)
	<-timer.C()
}
