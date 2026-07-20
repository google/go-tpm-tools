package logging

import (
	"bytes"
	"context"
	"io"
	"net"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// blockingWriter simulates a frozen destination (e.g., stalled network or blocked socket).
type blockingWriter struct {
	mu      sync.Mutex
	blocked bool
	blockCh chan struct{}
	written bytes.Buffer
}

func newBlockingWriter(blocked bool) *blockingWriter {
	return &blockingWriter{
		blocked: blocked,
		blockCh: make(chan struct{}),
	}
}

func (bw *blockingWriter) Write(p []byte) (int, error) {
	bw.mu.Lock()
	if bw.blocked {
		bw.mu.Unlock()
		<-bw.blockCh // Block indefinitely until unblocked by test
		bw.mu.Lock()
	}
	defer bw.mu.Unlock()
	return bw.written.Write(p)
}

func (bw *blockingWriter) Unblock() {
	bw.mu.Lock()
	bw.blocked = false
	close(bw.blockCh)
	bw.mu.Unlock()
}

func TestAsyncWriter_NonBlockingUnderLatency(t *testing.T) {
	bw := newBlockingWriter(true) // Downstream is completely frozen
	bufferSize := 10              // Small buffer to trigger overflow quickly
	aw := NewAsyncWriter(bw, bufferSize)

	payload := []byte("workload log line\n")
	start := time.Now()

	// Enqueue more items than buffer capacity while downstream is frozen
	for i := 0; i < 50; i++ {
		n, err := aw.Write(payload)
		if err != nil {
			t.Fatalf("Write %d returned unexpected error: %v", i, err)
		}
		if n != len(payload) {
			t.Fatalf("Write %d returned short write: %d vs %d", i, n, len(payload))
		}
	}

	elapsed := time.Since(start)
	if elapsed > 100*time.Millisecond {
		t.Fatalf("AsyncWriter blocked the calling thread! Elapsed: %v", elapsed)
	}

	// Verify that excess packets were dropped and recorded accurately
	dropped := aw.DroppedBytes()
	expectedDroppedMin := uint64((50 - bufferSize) * len(payload))
	if dropped < expectedDroppedMin {
		t.Errorf("Expected at least %d dropped bytes, got %d", expectedDroppedMin, dropped)
	}
}

func TestAsyncWriter_GracefulShutdown(t *testing.T) {
	buf := &bytes.Buffer{}
	aw := NewAsyncWriter(buf, 100)

	msg := []byte("graceful flush test\n")
	aw.Write(msg)
	aw.Write(msg)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if err := aw.Close(ctx); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	expected := string(msg) + string(msg)
	if buf.String() != expected {
		t.Errorf("Expected target buffer %q, got %q", expected, buf.String())
	}
}

func BenchmarkAsyncWriterVsMultiWriter(b *testing.B) {
	payload := []byte("benchmark container stdout log payload\n")

	b.Run("Synchronous_MultiWriter", func(b *testing.B) {
		// Simulates synchronous latency per writer (e.g., slow write)
		w1 := &latencyWriter{latency: 10 * time.Microsecond}
		w2 := &latencyWriter{latency: 10 * time.Microsecond}
		mw := io.MultiWriter(w1, w2)

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			mw.Write(payload)
		}
	})

	b.Run("Asynchronous_AsyncWriter", func(b *testing.B) {
		w1 := &latencyWriter{latency: 10 * time.Microsecond}
		w2 := &latencyWriter{latency: 10 * time.Microsecond}
		aw := NewAsyncWriter(io.MultiWriter(w1, w2), 8192)
		defer aw.Close(context.Background())

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			aw.Write(payload)
		}
	})
}

type latencyWriter struct {
	latency time.Duration
}

func (lw *latencyWriter) Write(p []byte) (int, error) {
	time.Sleep(lw.latency)
	return len(p), nil
}

func TestAsyncWriter_SocketStallSimulation(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "mock_socket")

	// Start socket server
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("Failed to bind socket: %v", err)
	}
	defer listener.Close()

	// Spawn slow reader (simulating stalled journald u_str socket)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 1024)
		for {
			_, err := conn.Read(buf)
			if err != nil {
				break
			}
			time.Sleep(10 * time.Millisecond) // Slow reading latency
		}
	}()

	// Connect as client
	clientConn, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer clientConn.Close()

	// Wrap in AsyncWriter
	aw := NewAsyncWriter(clientConn, 10)
	defer aw.Close(context.Background())

	payload := []byte("workload HTTP log payload\n")
	start := time.Now()

	// Write 100 log lines to the slow socket
	for i := 0; i < 100; i++ {
		_, err := aw.Write(payload)
		if err != nil {
			t.Fatalf("Write %d failed: %v", i, err)
		}
	}

	elapsed := time.Since(start)
	if elapsed > 100*time.Millisecond {
		t.Fatalf("AsyncWriter blocked the calling thread for %v!", elapsed)
	}

	if aw.DroppedBytes() == 0 {
		t.Log("Note: No bytes dropped, queue had sufficient capacity.")
	} else {
		t.Logf("Successfully dropped %d bytes without blocking client.", aw.DroppedBytes())
	}
}
