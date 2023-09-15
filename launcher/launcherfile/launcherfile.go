// Package launcherfile contains functions and constants for interacting with
// launcher files.
package launcherfile

const (
	// HostTmpPath defined the directory in the host that will store attestation tokens
	HostTmpPath = "/tmp/container_launcher/"
	// ContainerRuntimeMountPath defined the directory in the container stores attestation tokens
	ContainerRuntimeMountPath = "/run/container_launcher/"
	// AttestationVerifierTokenFilename defines the name of the file the attestation token is stored in.
	AttestationVerifierTokenFilename = "attestation_verifier_claims_token"
)
