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
			input: "{\"EnableTestFeatureForImage\":true,\"EnableItaVerifier\":true}",
			expectedExps: Experiments{
				EnableTestFeatureForImage: true,
				EnableItaVerifier:         true,
			},
		},
		{
			input: "{\"EnableTestFeatureForImage\":true,\"EnableSignedContainerImage\":true,\"EnableItaVerifier\":true,\"FloatFeature\":-5.6,\"OtherTestFeatureForImage\":false,\"EnableVerifyCS\":true}",
			expectedExps: Experiments{
				EnableTestFeatureForImage: true,
				EnableItaVerifier:         true,
				EnableVerifyCS:            true,
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
