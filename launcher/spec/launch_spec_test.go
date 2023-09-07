package spec

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestLaunchSpecUnmarshalJSONHappyCases(t *testing.T) {
	var testCases = []struct {
		testName string
		mdsJSON  string
	}{
		{
			"HappyCase",
			`{
				"tee-cmd":"[\"--foo\",\"--bar\",\"--baz\"]",
				"tee-env-foo":"bar",
				"tee-image-reference":"docker.io/library/hello-world:latest",
				"tee-signed-image-repos":"docker.io/library/hello-world,gcr.io/cloudrun/hello",
				"tee-restart-policy":"Always",
				"tee-impersonate-service-accounts":"sv1@developer.gserviceaccount.com,sv2@developer.gserviceaccount.com",
				"tee-container-log-redirect":"true"
			}`,
		},
		{
			"HappyCaseWithExtraUnknownFields",
			`{
				"tee-cmd":"[\"--foo\",\"--bar\",\"--baz\"]",
				"tee-env-foo":"bar",
				"tee-unknown":"unknown",
				"unknown":"unknown",
				"tee-image-reference":"docker.io/library/hello-world:latest",
				"tee-signed-image-repos":"docker.io/library/hello-world,gcr.io/cloudrun/hello",
				"tee-restart-policy":"Always",
				"tee-impersonate-service-accounts":"sv1@developer.gserviceaccount.com,sv2@developer.gserviceaccount.com",
				"tee-container-log-redirect":"true"
			}`,
		},
	}

	want := &LaunchSpec{
		ImageRef:                   "docker.io/library/hello-world:latest",
		SignedImageRepos:           []string{"docker.io/library/hello-world", "gcr.io/cloudrun/hello"},
		RestartPolicy:              Always,
		Cmd:                        []string{"--foo", "--bar", "--baz"},
		Envs:                       []EnvVar{{"foo", "bar"}},
		ImpersonateServiceAccounts: []string{"sv1@developer.gserviceaccount.com", "sv2@developer.gserviceaccount.com"},
		LogRedirect:                Everywhere,
	}

	for _, testcase := range testCases {
		t.Run(testcase.testName, func(t *testing.T) {
			spec := &LaunchSpec{}
			if err := spec.UnmarshalJSON([]byte(testcase.mdsJSON)); err != nil {
				t.Fatal(err)
			}
			if !cmp.Equal(spec, want) {
				t.Errorf("LaunchSpec UnmarshalJSON got %+v, want %+v", spec, want)
			}
		})
	}
}

func TestLaunchSpecUnmarshalJSONBadInput(t *testing.T) {
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
		{
			"WrongLogRedirectLocation",
			`{
				"tee-image-reference":"docker.io/library/hello-world:latest",
				"tee-container-log-redirect":"badideas",
			}`,
		},
	}

	for _, testcase := range testCases {
		t.Run(testcase.testName, func(t *testing.T) {
			spec := &LaunchSpec{}
			if err := spec.UnmarshalJSON([]byte(testcase.mdsJSON)); err == nil {
				t.Fatal("expected JSON parsing err")
			}
		})
	}
}

func TestLaunchSpecUnmarshalJSONWithDefaultValue(t *testing.T) {
	mdsJSON := `{
		"tee-image-reference":"docker.io/library/hello-world:latest",
		"tee-impersonate-service-accounts":"",
		"tee-signed-image-repos":"",
		"tee-container-log-redirect":"",
		"tee-restart-policy":""
		}`

	spec := &LaunchSpec{}
	if err := spec.UnmarshalJSON([]byte(mdsJSON)); err != nil {
		t.Fatal(err)
	}

	want := &LaunchSpec{
		ImageRef:      "docker.io/library/hello-world:latest",
		RestartPolicy: Never,
		LogRedirect:   Nowhere,
	}

	if !cmp.Equal(spec, want) {
		t.Errorf("LaunchSpec UnmarshalJSON got %+v, want %+v", spec, want)
	}
}

func TestLaunchSpecUnmarshalJSONWithoutImageReference(t *testing.T) {
	mdsJSON := `{
		"tee-cmd":"[\"--foo\",\"--bar\",\"--baz\"]",
		"tee-env-foo":"bar",
		"tee-restart-policy":"Never"
		}`

	spec := &LaunchSpec{}
	if err := spec.UnmarshalJSON([]byte(mdsJSON)); err == nil || err != errImageRefNotSpecified {
		t.Fatalf("got %v error, but expected %v error", err, errImageRefNotSpecified)
	}
}
