// Package spec contains definition of some basic container launch specs needed to
// launch a container, provided by the operator.
package spec

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"cloud.google.com/go/compute/metadata"
	"github.com/google/go-tpm-tools/launcher/internal/experiments"
)

// RestartPolicy is the enum for the container restart policy.
type RestartPolicy string

func (p RestartPolicy) isValid() error {
	switch p {
	case Always, OnFailure, Never:
		return nil
	}
	return fmt.Errorf("invalid restart policy: %s", p)
}

// Restart Policy enum values.
const (
	Always    RestartPolicy = "Always"
	OnFailure RestartPolicy = "OnFailure"
	Never     RestartPolicy = "Never"
)

// LogRedirectLocation specifies the workload logging redirect location.
type LogRedirectLocation string

func (l LogRedirectLocation) isValid() error {
	switch l {
	case Everywhere, CloudLogging, Serial, Nowhere:
		return nil
	}
	return fmt.Errorf("invalid logging redirect location %s, expect one of %s", l,
		[]LogRedirectLocation{Everywhere, CloudLogging, Serial, Nowhere})
}

func (l LogRedirectLocation) enabled() bool {
	return l != Nowhere
}

// LogRedirectLocation acceptable values.
const (
	Everywhere   LogRedirectLocation = "true"
	CloudLogging LogRedirectLocation = "cloud_logging"
	Serial       LogRedirectLocation = "serial"
	Nowhere      LogRedirectLocation = "false"
)

// Metadata variable names.
const (
	imageRefKey                = "tee-image-reference"
	signedImageRepos           = "tee-signed-image-repos"
	restartPolicyKey           = "tee-restart-policy"
	cmdKey                     = "tee-cmd"
	envKeyPrefix               = "tee-env-"
	impersonateServiceAccounts = "tee-impersonate-service-accounts"
	attestationServiceAddrKey  = "tee-attestation-service-endpoint"
	logRedirectKey             = "tee-container-log-redirect"
)

const (
	instanceAttributesQuery = "instance/attributes/?recursive=true"
)

var errImageRefNotSpecified = fmt.Errorf("%s is not specified in the custom metadata", imageRefKey)

// EnvVar represent a single environment variable key/value pair.
type EnvVar struct {
	Name  string
	Value string
}

// LaunchSpec contains specification set by the operator who wants to
// launch a container.
type LaunchSpec struct {
	// MDS-based values.
	ImageRef                   string
	SignedImageRepos           []string
	RestartPolicy              RestartPolicy
	Cmd                        []string
	Envs                       []EnvVar
	AttestationServiceAddr     string
	ImpersonateServiceAccounts []string
	ProjectID                  string
	Region                     string
	Hardened                   bool
	LogRedirect                LogRedirectLocation
	Experiments                experiments.Experiments
}

// UnmarshalJSON unmarshals an instance attributes list in JSON format from the metadata
// server set by an operator to a LaunchSpec.
func (s *LaunchSpec) UnmarshalJSON(b []byte) error {
	var unmarshaledMap map[string]string
	if err := json.Unmarshal(b, &unmarshaledMap); err != nil {
		return err
	}

	s.ImageRef = unmarshaledMap[imageRefKey]
	if s.ImageRef == "" {
		return errImageRefNotSpecified
	}

	s.RestartPolicy = RestartPolicy(unmarshaledMap[restartPolicyKey])
	// set the default restart policy to "Never" for now
	if s.RestartPolicy == "" {
		s.RestartPolicy = Never
	}
	if err := s.RestartPolicy.isValid(); err != nil {
		return err
	}

	if val, ok := unmarshaledMap[impersonateServiceAccounts]; ok && val != "" {
		impersonateAccounts := strings.Split(val, ",")
		s.ImpersonateServiceAccounts = append(s.ImpersonateServiceAccounts, impersonateAccounts...)
	}

	if val, ok := unmarshaledMap[signedImageRepos]; ok && val != "" {
		imageRepos := strings.Split(val, ",")
		s.SignedImageRepos = append(s.SignedImageRepos, imageRepos...)
	}

	// populate cmd override
	if val, ok := unmarshaledMap[cmdKey]; ok && val != "" {
		if err := json.Unmarshal([]byte(val), &s.Cmd); err != nil {
			return err
		}
	}

	// populate all env vars
	for k, v := range unmarshaledMap {
		if strings.HasPrefix(k, envKeyPrefix) {
			s.Envs = append(s.Envs, EnvVar{strings.TrimPrefix(k, envKeyPrefix), v})
		}
	}

	s.LogRedirect = LogRedirectLocation(unmarshaledMap[logRedirectKey])
	// Default log redirect location is Nowhere ("false").
	if s.LogRedirect == "" {
		s.LogRedirect = Nowhere
	}
	if err := s.LogRedirect.isValid(); err != nil {
		return err
	}

	s.AttestationServiceAddr = unmarshaledMap[attestationServiceAddrKey]

	return nil
}

func getRegion(client *metadata.Client) (string, error) {
	zone, err := client.Zone()
	if err != nil {
		return "", fmt.Errorf("failed to retrieve zone from MDS: %v", err)
	}
	lastDash := strings.LastIndex(zone, "-")
	if lastDash == -1 {
		return "", fmt.Errorf("got malformed zone from MDS: %v", zone)
	}
	return zone[:lastDash], nil
}

// GetLaunchSpec takes in a metadata server client, reads and parse operator's
// input to the GCE instance custom metadata and return a LaunchSpec.
// ImageRef (tee-image-reference) is required, will return an error if
// ImageRef is not presented in the metadata.
func GetLaunchSpec(client *metadata.Client) (LaunchSpec, error) {
	data, err := client.Get(instanceAttributesQuery)
	if err != nil {
		return LaunchSpec{}, err
	}

	spec := &LaunchSpec{}
	if err := spec.UnmarshalJSON([]byte(data)); err != nil {
		return LaunchSpec{}, err
	}

	spec.ProjectID, err = client.ProjectID()
	if err != nil {
		return LaunchSpec{}, fmt.Errorf("failed to retrieve projectID from MDS: %v", err)
	}

	spec.Region, err = getRegion(client)
	if err != nil {
		return LaunchSpec{}, err
	}

	kernelCmd, err := readCmdline()
	if err != nil {
		return LaunchSpec{}, err
	}
	spec.Hardened = isHardened(kernelCmd)

	return *spec, nil
}

func isHardened(kernelCmd string) bool {
	for _, arg := range strings.Fields(kernelCmd) {
		if arg == "confidential-space.hardened=true" {
			return true
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
