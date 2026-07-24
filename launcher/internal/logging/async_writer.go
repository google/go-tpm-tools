package logging

import (
	"context"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
)

const (
	defaultAsyncBufferSize = 8192
)

// AsyncWriter wraps an underlying io.Writer (or Logger) and writes asynchronously
// using a bounded channel buffer to prevent blocking the caller under high-QPS bursts.
type AsyncWriter struct {
	target       io.Writer
	ch           chan []byte
	droppedBytes atomic.Uint64
	wg           sync.WaitGroup
	closed       bool
	mu           sync.RWMutex
}

// NewAsyncWriter creates an AsyncWriter with the given buffer size wrapping target.
func NewAsyncWriter(target io.Writer, bufferSize int) *AsyncWriter {
	if bufferSize <= 0 {
		bufferSize = defaultAsyncBufferSize
	}
	aw := &AsyncWriter{
		target: target,
		ch:     make(chan []byte, bufferSize),
	}
	aw.wg.Add(1)
	go aw.drain()
	return aw
}

// Write implements io.Writer. It never blocks; if the buffer is full, bytes are dropped and counted.
func (aw *AsyncWriter) Write(p []byte) (int, error) {
	aw.mu.RLock()
	defer aw.mu.RUnlock()

	if aw.closed {
		return len(p), nil
	}

	// Make a copy since caller may reuse the slice buffer after Write() returns.
	buf := make([]byte, len(p))
	copy(buf, p)

	select {
	case aw.ch <- buf:
	default:
		// Buffer full: drop packet to avoid I/O bottlenecks on container stdout/stderr pipe.
		aw.droppedBytes.Add(uint64(len(p)))
	}
	return len(p), nil
}

func (aw *AsyncWriter) drain() {
	defer aw.wg.Done()
	for buf := range aw.ch {
		if _, err := aw.target.Write(buf); err != nil {
			slog.Debug("AsyncWriter target write failed", "err", err)
		}
	}
}

// DroppedBytes returns the total number of bytes dropped due to buffer overflow.
func (aw *AsyncWriter) DroppedBytes() uint64 {
	return aw.droppedBytes.Load()
}

// Close gracefully closes the channel and waits for pending entries to drain with a timeout.
func (aw *AsyncWriter) Close(ctx context.Context) error {
	aw.mu.Lock()
	if aw.closed {
		aw.mu.Unlock()
		return nil
	}
	aw.closed = true
	close(aw.ch)
	aw.mu.Unlock()

	done := make(chan struct{})
	go func() {
		aw.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		if dropped := aw.DroppedBytes(); dropped > 0 {
			slog.Warn("AsyncWriter closed with dropped workload logs", "dropped_bytes", dropped)
		}
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
