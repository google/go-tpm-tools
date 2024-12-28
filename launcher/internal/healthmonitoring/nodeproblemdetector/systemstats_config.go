// Package nodeproblemdetector provides configurations for node-problem-detector.service.
package nodeproblemdetector

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/google/go-tpm-tools/launcher/internal/logging"
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

type diskConfig struct {
	IncludeAllAttachedBlk bool         `json:"includeAllAttachedBlk"`
	IncludeRootBlk        bool         `json:"includeRootBlk"`
	LsblkTimeout          string       `json:"lsblkTimeout"`
	MetricsConfigs        *statsConfig `json:"metricsConfigs"`
}

// SystemStatsConfig contains configurations for `System Stats Monitor`,
// a problem daemon in node-problem-detector that collects pre-defined health-related metrics from different system components.
// View the comprehensive configuration details on https://github.com/kubernetes/node-problem-detector/tree/master/pkg/systemstatsmonitor#detailed-configuration-options
type SystemStatsConfig struct {
	CPU            *statsConfig `json:"cpu,omitempty"`
	Disk           *diskConfig  `json:"disk,omitempty"`
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

var allConfig = &SystemStatsConfig{
	CPU: &statsConfig{map[string]metricConfig{
		"cpu/usage_time": {"cpu/usage_time"},
		"cpu/load_1m":    {"cpu/load_1m"},
	}},
	Disk: &diskConfig{
		true, true, "5s",
		&statsConfig{map[string]metricConfig{
			"disk/io_time": {"disk/io_time"},
		}},
	},
	Host: &statsConfig{map[string]metricConfig{
		"host/uptime": {"host/uptime"},
	}},
	Memory: &statsConfig{map[string]metricConfig{
		"memory/bytes_used": {"memory/bytes_used"},
	}},
	InvokeInterval: defaultInvokeIntervalString,
}

// EnableAllConfig overwrites system stats config with health monitoring config.
func EnableAllConfig() error {
	return allConfig.WriteFile(systemStatsFilePath)
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
func StartService(logger logging.Logger) error {
	s, err := systemctl.New()
	if err != nil {
		return fmt.Errorf("failed to create systemctl client: %v", err)
	}
	defer s.Close()

	logger.Info("Starting node-problem-detector.service")
	if err := s.Start("node-problem-detector.service"); err != nil {
		return fmt.Errorf("failed to start node-problem-detector.service")
	}

	logger.Info("node-problem-detector.service successfully started")
	return nil
}
