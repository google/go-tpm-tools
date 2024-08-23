// Package nodeproblemdetector provides configurations for node-problem-detector.service.
package nodeproblemdetector

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/google/go-tpm-tools/launcher/internal/systemctl"
)

var systemStatsFilePath = "/etc/node_problem_detector/system-stats-monitor.json"

var defaultInvokeIntervalString = (60 * time.Second).String()

type metricConfig struct {
	DisplayName string `json:"displayName"`
}

type statsConfig struct {
	MetricsConfigs map[string]metricConfig `json:"metricsConfigs"`
}

// SystemStatsConfig contains configurations for `System Stats Monitor`,
// a problem daemon in node-problem-detector that collects pre-defined health-related metrics from different system components.
// For now we only consider collecting memory related metrics.
// View the comprehensive configuration details on https://github.com/kubernetes/node-problem-detector/tree/master/pkg/systemstatsmonitor#detailed-configuration-options
type SystemStatsConfig struct {
	CPU            *statsConfig `json:"cpu,omitempty"`
	Disk           *statsConfig `json:"disk,omitempty"`
	Host           *statsConfig `json:"host,omitempty"`
	Memory         *statsConfig `json:"memory,omitempty"`
	InvokeInterval string       `json:"invokeInterval,omitempty"`
}

// NewSystemStatsConfig returns a new SystemStatsConfig struct with default configurations.
func NewSystemStatsConfig() SystemStatsConfig {
	return SystemStatsConfig{
		Memory:         &statsConfig{MetricsConfigs: map[string]metricConfig{}},
		InvokeInterval: defaultInvokeIntervalString,
	}
}

var healthConfig = &SystemStatsConfig{
	CPU: &statsConfig{map[string]metricConfig{
		"cpu/load_5m": {"cpu/load_5m"},
	}},
	Disk: &statsConfig{map[string]metricConfig{
		"disk/percent_used": {"disk/percent_used"},
	}},
	Host: &statsConfig{map[string]metricConfig{
		"host/uptime": {"host/uptime"},
	}},
	Memory: &statsConfig{map[string]metricConfig{
		"memory/bytes_used": {"memory/bytes_used"},
	}},
	InvokeInterval: defaultInvokeIntervalString,
}

// EnableHealthMonitoringConfig overwrites system stats config with health monitoring config.
func EnableHealthMonitoringConfig() error {
	return healthConfig.WriteFile(systemStatsFilePath)
}

// EnableMemoryBytesUsed enables "memory/bytes_used" for memory monitoring.
func (ssc *SystemStatsConfig) EnableMemoryBytesUsed() {
	ssc.Memory.MetricsConfigs["memory/bytes_used"] = metricConfig{DisplayName: "memory/bytes_used"}
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

// StartService starts Node Problem Detector.
func StartService(logger *log.Logger) error {
	s, err := systemctl.New()
	if err != nil {
		return fmt.Errorf("failed to create systemctl client: %v", err)
	}
	defer s.Close()

	logger.Printf("Starting node-problem-detector.service")
	if err := s.Start("node-problem-detector.service"); err != nil {
		return fmt.Errorf("failed to start node-problem-detector.service")
	}

	logger.Printf("node-problem-detector.service successfully started")
	return nil
}
