// Package spec contains definition of some basic container launcher specs needed to
// launch a container, provided by the operator.
package spec

import (
	"encoding/json"
	"fmt"
	"strings"

	"cloud.google.com/go/compute/metadata"
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

const (
	defaultAttestationServiceEndpoint = "attestation-verifier.confidential-computing-test-org.joonix.net:9090"
)

const (
	imageRefKey                = "tee-image-reference"
	restartPolicyKey           = "tee-restart-policy"
	cmdKey                     = "tee-cmd"
	envKeyPrefix               = "tee-env-"
	impersonateServiceAccounts = "tee-impersonate-service-accounts"
	attestationServiceAddrKey  = "tee-attestation-service-endpoint"
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

// LauncherSpec contains specification set by the operator who wants to
// launch a container.
type LauncherSpec struct {
	ImageRef                   string
	RestartPolicy              RestartPolicy
	Cmd                        []string
	Envs                       []EnvVar
	AttestationServiceAddr     string
	ImpersonateServiceAccounts []string
}

// UnmarshalJSON unmarshals an instance attributes list in JSON format from the metadata
// server set by an operator to a LauncherSpec.
func (s *LauncherSpec) UnmarshalJSON(b []byte) error {
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

	s.AttestationServiceAddr = unmarshaledMap[attestationServiceAddrKey]

	return nil
}

// GetLauncherSpec takes in a metadata server client, reads and parse operator's
// input to the GCE instance custom metadata and return a LauncherSpec.
// ImageRef (tee-image-reference) is required, will return an error if
// ImageRef is not presented in the metadata.
func GetLauncherSpec(client *metadata.Client) (LauncherSpec, error) {
	data, err := client.Get(instanceAttributesQuery)
	if err != nil {
		return LauncherSpec{}, err
	}

	spec := &LauncherSpec{}
	if err := spec.UnmarshalJSON([]byte(data)); err != nil {
		return LauncherSpec{}, err
	}

	if spec.AttestationServiceAddr == "" {
		spec.AttestationServiceAddr = defaultAttestationServiceEndpoint
	}

	return *spec, nil
}
