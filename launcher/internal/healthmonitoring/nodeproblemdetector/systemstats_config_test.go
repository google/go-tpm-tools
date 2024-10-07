package nodeproblemdetector

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

func TestEnableHealthMonitoringConfig(t *testing.T) {
	tmpDir := t.TempDir()
	systemStatsFilePath = path.Join(tmpDir, "system-stats-monitor.json")

	wantBytes, err := json.Marshal(allConfig)
	if err != nil {
		t.Fatalf("Error marshaling expected config: %v", err)
	}

	EnableAllConfig()

	file, err := os.OpenFile(systemStatsFilePath, os.O_RDONLY, 0)
	if err != nil {
		t.Fatalf("failed to open file %s: %v", systemStatsFilePath, err)
	}

	gotBytes, err := io.ReadAll(file)
	if err != nil {
		t.Fatalf("failed to read from file %s: %v", systemStatsFilePath, err)
	}

	if !bytes.Equal(gotBytes, wantBytes) {
		t.Errorf("WriteFile() did not write expected contents, got %s, want %s", gotBytes, wantBytes)
	}
}

func TestEnableMemoryBytesUsed(t *testing.T) {
	got := NewSystemStatsConfig()
	got.EnableMemoryBytesUsed()

	want := SystemStatsConfig{
		Memory: &statsConfig{
			MetricsConfigs: map[string]metricConfig{
				"memory/bytes_used": {DisplayName: "memory/bytes_used"},
			},
		},
		InvokeInterval: defaultInvokeIntervalString,
	}
	if !cmp.Equal(got, want) {
		t.Errorf("EnableMemoryBytesUsed() failed, got: %v, want: %v", got, want)
	}
}

func TestWithInvokeInterval(t *testing.T) {
	got := SystemStatsConfig{}
	got.WithInvokeInterval(2 * time.Second)

	want := SystemStatsConfig{InvokeInterval: (2 * time.Second).String()}
	if !cmp.Equal(got, want) {
		t.Errorf("WithInvokeInterval() failed, got: %v, want: %v", got, want)
	}
}

func TestWriteFile(t *testing.T) {
	tmpDir := t.TempDir()
	tmpConfigFile := path.Join(tmpDir, "system-stats-monitor.json")

	config := NewSystemStatsConfig()
	config.EnableMemoryBytesUsed()
	if err := config.WriteFile(tmpConfigFile); err != nil {
		t.Fatalf("WriteFile() failed: %v", err)
	}

	file, err := os.OpenFile(tmpConfigFile, os.O_RDONLY, 0)
	if err != nil {
		t.Fatalf("failed to open file %s: %v", tmpConfigFile, err)
	}

	gotBytes, err := io.ReadAll(file)
	if err != nil {
		t.Fatalf("failed to read from file %s: %v", tmpConfigFile, err)
	}

	wantBytes := []byte(`{"memory":{"metricsConfigs":{"memory/bytes_used":{"displayName":"memory/bytes_used"}}},"invokeInterval":"1m0s"}`)
	if !bytes.Equal(gotBytes, wantBytes) {
		t.Errorf("WriteFile() did not write expected contents, got %s, want %s", gotBytes, wantBytes)
	}
}
