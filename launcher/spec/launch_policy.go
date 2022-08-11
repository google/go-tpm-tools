package spec

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

type LogRedirectPolicyType uint8

const (
	LogRedirectDebugOnly LogRedirectPolicyType = iota
	LogRedirctFalse
	LogRedirctTrue
)

// LaunchPolicy contains policies on starting the container.
// The policy comes from the labels of the image.
type LaunchPolicy struct {
	AllowedEnvOverride []string
	AllowedCmdOverride bool
	LogRedirect        bool
}

const (
	envOverride = "tee.launch_policy.allow_env_override"
	cmdOverride = "tee.launch_policy.allow_cmd_override"
	logRedirect = "tee.launch_policy.log_redirect"
)

// GetLaunchPolicy takes in a map[string] string which should come from image labels,
// and will try to parse it into a LaunchPolicy. Extra fields will be ignored.
func GetLaunchPolicy(imageLabels map[string]string) (LaunchPolicy, error) {
	var err error
	launchPolicy := LaunchPolicy{}
	if v, ok := imageLabels[envOverride]; ok {
		envs := strings.Split(v, ",")
		for _, env := range envs {
			// strip out empty env name
			if env != "" {
				launchPolicy.AllowedEnvOverride = append(launchPolicy.AllowedEnvOverride, env)
			}
		}
	}

	if v, ok := imageLabels[cmdOverride]; ok {
		if launchPolicy.AllowedCmdOverride, err = strconv.ParseBool(v); err != nil {
			return LaunchPolicy{}, fmt.Errorf("value of LABEL %s of the image is not a boolean: %s", cmdOverride, v)
		}
	}

	if v, ok := imageLabels[logRedirect]; ok {
		if launchPolicy.LogRedirect, err = strconv.ParseBool(v); err != nil {
			if strings.ToUpper(v) == "DEBUGONLY" {
				if IsHardened() {
					launchPolicy.LogRedirect = false
				} else {
					launchPolicy.LogRedirect = true
				}
			} else {
				return LaunchPolicy{}, fmt.Errorf("value of LABEL %s of the image is not one of True/False/DebugOnly: %s", logRedirect, v)
			}
		}
	} else {
		if IsHardened() {
			launchPolicy.LogRedirect = false
		} else {
			launchPolicy.LogRedirect = true
		}
	}

	return launchPolicy, nil
}

// Verify will use the LaunchPolicy to verify the given LauncherSpec. If the verification passed, will return nil.
// If there are multiple violations, the function will return the first error.
func (p LaunchPolicy) Verify(ls LauncherSpec) error {
	for _, e := range ls.Envs {
		if !contains(p.AllowedEnvOverride, e.Name) {
			return fmt.Errorf("env var %s is not allowed to be overridden on this image; allowed envs to be overridden: %v", e, p.AllowedEnvOverride)
		}
	}
	if !p.AllowedCmdOverride && len(ls.Cmd) > 0 {
		return fmt.Errorf("CMD is not allowed to be overridden on this image")
	}

	return nil
}

func contains(strs []string, target string) bool {
	for _, s := range strs {
		if s == target {
			return true
		}
	}
	return false
}

// IsHardened determine current enviornemnt is in a hardended OS
func IsHardened() bool {
	kernelCmd, err := readCmdline()
	// if failed to read cmdline, default to non-prod
	if err != nil {
		fmt.Println(err)
		return false
	}
	args := strings.Fields(kernelCmd)

	for _, arg := range args {
		if strings.HasPrefix(arg, "confidential-space.env=") {
			return strings.HasSuffix(arg, "=hardended")
		}
	}
	return false
}

func readCmdline() (string, error) {
	kernelCmd, err := os.ReadFile("/proc/cmdline")
	if err != nil {
		return "", err
	}
	return string(kernelCmd), nil
}
