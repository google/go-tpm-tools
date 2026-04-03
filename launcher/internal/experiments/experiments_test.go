package experiments

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestExperiments(t *testing.T) {
	tests := []struct {
		input        string
		expectedExps Experiments
	}{
		{
			input: "{\"EnableH100DriverInstallation\":true,\"EnableB200DriverInstallation\":true,\"EnableTestFeatureForImage\":true,\"EnableItaVerifier\":true,\"EnableKeyManager\":false}",
			expectedExps: Experiments{
				EnableTestFeatureForImage:    true,
				EnableItaVerifier:            true,
				EnableB200DriverInstallation: true,
				EnableH100DriverInstallation: true,
				EnableKeyManager:             false,
				EnableGpuGcaSupport:          false,
			},
		},
		{
			input: "{\"EnableB200DriverInstallation\":true}",
			expectedExps: Experiments{
				EnableB200DriverInstallation: true,
				EnableKeyManager:             false,
				EnableGpuGcaSupport:          false,
				EnableHostAttestation:        false,
			},
		},
		{
			input: "{\"EnableTestFeatureForImage\":true,\"EnableSignedContainerImage\":true,\"EnableItaVerifier\":true,\"FloatFeature\":-5.6,\"OtherTestFeatureForImage\":false,\"EnableHostAttestation\":true}",
			expectedExps: Experiments{
				EnableTestFeatureForImage: true,
				EnableItaVerifier:         true,
				EnableGpuGcaSupport:       false,
				EnableHostAttestation:     true,
			},
		},
		{
			input: "{\"EnableB200DriverInstallation\":true,\"EnableKeyManager\":true}",
			expectedExps: Experiments{
				EnableB200DriverInstallation: true,
				EnableKeyManager:             true,
				EnableGpuGcaSupport:          false,
			},
		},
		{
			input: "{\"EnableGpuGcaSupport\":true,\"EnableH100DriverInstallation\":true,\"EnableB200DriverInstallation\":false,\"EnableTestFeatureForImage\":true,\"EnableItaVerifier\":true,\"EnableKeyManager\":false}",
			expectedExps: Experiments{
				EnableTestFeatureForImage:    true,
				EnableItaVerifier:            true,
				EnableB200DriverInstallation: false,
				EnableH100DriverInstallation: true,
				EnableKeyManager:             false,
				EnableGpuGcaSupport:          true,
			},
		},
		{
			input: "{\"EnableTestFeatureForImage\":true,\"EnableItaVerifier\":false,\"NonExistantExperiment\":true,\"EnableVerifyCS\":true}",
			expectedExps: Experiments{
				EnableTestFeatureForImage: true,
				EnableItaVerifier:         false,
			},
		},
	}

	for i, test := range tests {
		e, err := readJSONInput([]byte(test.input))

		if err != nil {
			t.Fatalf("testcase %d: failed to create experiments object: %v", i, err)
		}

		if !cmp.Equal(e, test.expectedExps) {
			t.Errorf("testcase %d: unexpected experiments returned: got %v, want %v", i, e, test.expectedExps)
		}
	}
}

func TestExperimentsBadJson(t *testing.T) {
	tests := []struct {
		input string
	}{
		{input: "{\"EnableTestFeatureForImage\":true,\"EnableSignedContainerImage\":true"},
		{input: "{}"},
		{input: ""},
	}

	for i, test := range tests {
		e, _ := readJSONInput([]byte(test.input))

		if e.EnableTestFeatureForImage {
			t.Errorf("testcase %d: expected EnableTestFeatureForImage to be false, got true", i)
		}
	}
}
