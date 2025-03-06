package models

import (
	"fmt"
	"testing"
	"time"
)

func TestRealTimerFires(t *testing.T) {
	timer := NewRealTimer(100 * time.Millisecond)
	time.Sleep(125 * time.Millisecond)
	<-timer.C()

	fmt.Printf("%v\n", timer.Reset(100*time.Millisecond))
	time.Sleep(125 * time.Millisecond)
	<-timer.C()
}

func TestRealTimerFiresInstantly(t *testing.T) {
	timer := NewRealTimer(0)
	<-timer.C()

	fmt.Printf("%v\n", timer.Reset(100*time.Millisecond))
	time.Sleep(125 * time.Millisecond)
	<-timer.C()
}
