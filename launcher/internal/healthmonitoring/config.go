package monitoring

import (
	"fmt"
	"strings"
)

type Config struct {
	CPU    bool
	Disk   bool
	Host   bool
	Memory bool
}

func AllConfig() Config {
	return Config{CPU: true, Disk: true, Host: true, Memory: true}
}

func NoneConfig() Config {
	return Config{CPU: false, Disk: false, Host: false, Memory: false}
}

func ToConfig(data string) (Config, error) {
	// We currently only support a single value for this field.
	switch strings.ToLower(data) {
	case "none":
		return NoneConfig(), nil
	case "all":
		return AllConfig(), nil
	case "memory":
		return Config{Memory: true}, nil
	}

	return Config{}, fmt.Errorf("invalid monitoring type: %v", data)
}

// Verifies that each monitoring component enabled by spec is also enabled by policy.
func CheckCompliance(policy Config, spec Config) error {
	invalidConfigs := []string{}

	if !policy.CPU && spec.CPU {
		invalidConfigs = append(invalidConfigs, "CPU")
	}

	if !policy.Disk && spec.Disk {
		invalidConfigs = append(invalidConfigs, "DISK")
	}

	if !policy.Host && spec.Host {
		invalidConfigs = append(invalidConfigs, "HOST")
	}

	if !policy.Memory && spec.Memory {
		invalidConfigs = append(invalidConfigs, "MEMORY")
	}

	if len(invalidConfigs) > 0 {
		return fmt.Errorf("the following monitoring types were enabled, but disallowed by launch policy: %v", invalidConfigs)
	}

	return nil
}
