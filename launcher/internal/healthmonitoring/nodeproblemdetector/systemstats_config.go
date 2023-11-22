// Package nodeproblemdetector provides configurations for node-problem-detector.service.
package nodeproblemdetector

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

var defaultInvokeIntervalString = (60 * time.Second).String()

type metricConfig struct {
	DisplayName string `json:"displayName"`
}

type memoryStatsConfig struct {
	MetricsConfigs map[string]metricConfig `json:"metricsConfigs"`
}

// SystemStatsConfig contains configurations for `System Stats Monitor`,
// a problem daemon in node-problem-detector that collects pre-defined health-related metrics from different system components.
// For now we only consider collecting memory related metrics.
// View the comprehensive configuration details on https://github.com/kubernetes/node-problem-detector/tree/master/pkg/systemstatsmonitor#detailed-configuration-options
type SystemStatsConfig struct {
	MemoryStatsConfig memoryStatsConfig `json:"memory"`
	InvokeInterval    string            `json:"invokeInterval"`
}

// NewSystemStatsConfig returns a new SystemStatsConfig struct with default configurations.
func NewSystemStatsConfig() SystemStatsConfig {
	return SystemStatsConfig{
		MemoryStatsConfig: memoryStatsConfig{MetricsConfigs: map[string]metricConfig{}},
		InvokeInterval:    defaultInvokeIntervalString,
	}
}

// EnableMemoryBytesUsed enables "memory/bytes_used" for memory monitoring.
func (ssc *SystemStatsConfig) EnableMemoryBytesUsed() {
	ssc.MemoryStatsConfig.MetricsConfigs["memory/bytes_used"] = metricConfig{DisplayName: "memory/bytes_used"}
}

// WithInvokeInterval overrides the default invokeInterval.
func (ssc *SystemStatsConfig) WithInvokeInterval(interval time.Duration) {
	ssc.InvokeInterval = interval.String()
}

// WriteFile writes systemStatsConfig data to the named file, creating it if necessary.
func (ssc *SystemStatsConfig) WriteFile(path string) error {
	bytes, err := json.Marshal(ssc)
	if err != nil {
		return fmt.Errorf("failed to marshal struct [%v]: %w", ssc, err)
	}
	return os.WriteFile(path, bytes, 0644)
}
