package spec

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestLauncherSpecUnmarshalJSONHappyCases(t *testing.T) {
	var testCases = []struct {
		testName string
		mdsJSON  string
	}{
		{
			"HappyCase",
			`{
				"tee-cmd":"[\"--foo\",\"--bar\",\"--baz\"]",
				"tee-env-enva":"aaa",
				"tee-image-reference":"docker.io/library/hello-world:latest",
				"tee-restart-policy":"Always"
			}`,
		},
		{
			"HappyCaseWithExtraUnknowFields",
			`{
				"tee-cmd":"[\"--foo\",\"--bar\",\"--baz\"]",
				"tee-env-enva":"aaa",
				"tee-unknown":"unknown",
				"unknown":"unknown",
				"tee-image-reference":"docker.io/library/hello-world:latest",
				"tee-restart-policy":"Always"
			}`,
		},
	}

	want := &LauncherSpec{
		ImageRef:      "docker.io/library/hello-world:latest",
		RestartPolicy: Always,
		Cmd:           []string{"--foo", "--bar", "--baz"},
		Envs:          []EnvVar{{"enva", "aaa"}},
	}

	for _, testcase := range testCases {
		t.Run(testcase.testName, func(t *testing.T) {
			spec := &LauncherSpec{}
			if err := spec.UnmarshalJSON([]byte(testcase.mdsJSON)); err != nil {
				t.Fatal(err)
			}
			if !cmp.Equal(spec, want) {
				t.Errorf("LauncherSpec UnmarshalJSON got %+v, want %+v", spec, want)
			}
		})
	}
}

func TestLauncherSpecUnmarshalJSONBadInput(t *testing.T) {
	var testCases = []struct {
		testName string
		mdsJSON  string
	}{
		// not likely to happen for MDS
		{
			"BadJSON",
			`{
				BadJSONFormat
			}`,
		},
		// when there is no MDS values
		{
			"EmptyJSON",
			`{}`,
		},
		// not likely to happen, since MDS will always use string as the value
		{
			"JSONWithPrimitives",
			`{
				"tee-env-bool":true,
				"tee-image-reference":"docker.io/library/hello-world:latest"
			}`,
		},
		{
			"WrongRestartPolicy",
			`{
				"tee-image-reference":"docker.io/library/hello-world:latest",
				"tee-restart-policy":"noway",
			}`,
		},
	}

	for _, testcase := range testCases {
		t.Run(testcase.testName, func(t *testing.T) {
			spec := &LauncherSpec{}
			if err := spec.UnmarshalJSON([]byte(testcase.mdsJSON)); err == nil {
				t.Fatal("expected JSON parsing err")
			}
		})
	}
}

func TestLauncherSpecUnmarshalJSONWithDefaultValue(t *testing.T) {
	mdsJSON := `{"tee-image-reference":"docker.io/library/hello-world:latest"}`

	spec := &LauncherSpec{}
	if err := spec.UnmarshalJSON([]byte(mdsJSON)); err != nil {
		t.Fatal(err)
	}

	want := &LauncherSpec{
		ImageRef:      "docker.io/library/hello-world:latest",
		RestartPolicy: Never,
		Cmd:           nil,
		Envs:          nil,
	}

	if !cmp.Equal(spec, want) {
		t.Errorf("LauncherSpec UnmarshalJSON got %+v, want %+v", spec, want)
	}
}

func TestLauncherSpecUnmarshalJSONWithoutImageReference(t *testing.T) {
	mdsJSON := `{
		"tee-cmd":"[\"--foo\",\"--bar\",\"--baz\"]",
		"tee-env-enva":"aaa",
		"tee-restart-policy":"Never"
		}`

	spec := &LauncherSpec{}
	if err := spec.UnmarshalJSON([]byte(mdsJSON)); err == nil || err != errImageRefNotSpecified {
		t.Fatalf("got %v error, but expected %v error", err, errImageRefNotSpecified)
	}
}
