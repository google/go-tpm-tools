package experiments

import (
	"testing"
)

func TestExperiments(t *testing.T) {
	tests := []struct {
		input string
	}{
		{input: "{\"EnableTestFeatureForImage\":true,\"EnableSignedContainerImage\":true,\"EnableItaVerifier\":true}"},
		{input: "{\"EnableTestFeatureForImage\":true,\"EnableSignedContainerImage\":true,\"EnableItaVerifier\":true,\"FloatFeature\":-5.6,\"OtherTestFeatureForImage\":false}"},
	}

	for i, test := range tests {
		e, err := readJSONInput([]byte(test.input))

		if err != nil {
			t.Errorf("testcase %d: failed to create experiments object: %v", i, err)
		}

		if e.EnableTestFeatureForImage == false {
			t.Errorf("testcase %d: expected EnableTestFeatureForImage to be true, got false", i)
		}

		if !e.EnableItaVerifier {
			t.Errorf("testcase %d: expected EnableItaVerifier to be true, got false", i)
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

		if e.EnableTestFeatureForImage == true {
			t.Errorf("testcase %d: expected EnableTestFeatureForImage to be false, got true", i)
		}
	}
}
