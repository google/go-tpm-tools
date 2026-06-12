// Provides common log filtering functionality to redact sensitive fields before they are written to logs.

package logging

import (
	"strings"

	"github.com/google/go-tpm-tools/launcher/spec"
)

func []string filterEnvs(envs []spec.EnvVar) {
	var safeEnvs []string
	for _, env := range envs {
		parts := strings.SplitN(env, "=", 2)
		if len(parts) == 2 {
			safeEnvs = append(safeEnvs, parts[0]+"=[REDACTED]")
		} else {
			safeEnvs = append(safeEnvs, env)
		}
	}
	return safeEnvs
}