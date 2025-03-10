package models

import (
	"testing"
	"time"
)

func TestRealTimerFires(t *testing.T) {
	timer := NewRealTimer()

	dur := 250 * time.Millisecond
	timer.Reset(dur)
	time.Sleep(dur + 25*time.Millisecond)

	<-timer.C()
}
