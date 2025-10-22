package clock

import (
	"fmt"
	"testing"
	"time"
)

func TestRealTimerFires(_ *testing.T) {
	timer := NewRealTimer(100 * time.Millisecond)
	time.Sleep(125 * time.Millisecond)
	<-timer.C()

	fmt.Printf("%v\n", timer.Reset(100*time.Millisecond))
	time.Sleep(125 * time.Millisecond)
	<-timer.C()
}

func TestRealTimerFiresInstantly(_ *testing.T) {
	timer := NewRealTimer(0)
	<-timer.C()

	timer.Reset(100 * time.Millisecond)
	time.Sleep(125 * time.Millisecond)
	<-timer.C()
}
