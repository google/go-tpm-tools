package spec

import (
	"regexp"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-tpm-tools/launcher/internal/experiments"
	"github.com/google/go-tpm-tools/launcher/internal/launchermount"
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
				"tee-container-log-redirect":"true",
				"tee-monitoring-memory-enable":"true",
				"tee-dev-shm-size-kb":"234234",
				"tee-mount":"type=tmpfs,source=tmpfs,destination=/tmpmount;type=tmpfs,source=tmpfs,destination=/sized,size=222"
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
				"tee-container-log-redirect":"true",
				"tee-monitoring-memory-enable":"TRUE",
				"tee-dev-shm-size-kb":"234234",
				"tee-mount":"type=tmpfs,source=tmpfs,destination=/tmpmount;type=tmpfs,source=tmpfs,destination=/sized,size=222"
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
		MemoryMonitoringEnabled:    true,
		DevShmSize:                 234234,
		Mounts: []launchermount.Mount{launchermount.TmpfsMount{Destination: "/tmpmount", Size: 0},
			launchermount.TmpfsMount{Destination: "/sized", Size: 222}},
		Experiments: experiments.Experiments{
			EnableTempFSMount: true,
		},
	}

	for _, testcase := range testCases {
		t.Run(testcase.testName, func(t *testing.T) {
			spec := &LaunchSpec{}
			spec.Experiments = experiments.Experiments{
				EnableTempFSMount: true,
			}
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
		"tee-restart-policy":"",
		"tee-monitoring-memory-enable":"",
		"tee-mount":""
		}`

	spec := &LaunchSpec{}
	if err := spec.UnmarshalJSON([]byte(mdsJSON)); err != nil {
		t.Fatal(err)
	}

	want := &LaunchSpec{
		ImageRef:                "docker.io/library/hello-world:latest",
		RestartPolicy:           Never,
		LogRedirect:             Nowhere,
		MemoryMonitoringEnabled: false,
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
		t.Errorf("got %v error, but expected %v error", err, errImageRefNotSpecified)
	}
}

func TestLaunchSpecUnmarshalJSONWithTmpfsMounts(t *testing.T) {
	var testCases = []struct {
		testName string
		mdsJSON  string
		wantDst  string
		wantSz   uint64
	}{
		{
			"Empty Mounts",
			`{
				"tee-image-reference":"docker.io/library/hello-world:latest",
				"tee-mount":""
			}`,
			"",
			0,
		},
		{
			"Tmpfs",
			`{
				"tee-image-reference":"docker.io/library/hello-world:latest",
				"tee-mount":"type=tmpfs,source=tmpfs,destination=/tmpmount"
			}`,
			"/tmpmount",
			0,
		},
		{
			"Tmpfs Sized",
			`{
				"tee-image-reference":"docker.io/library/hello-world:latest",
				"tee-mount":"type=tmpfs,source=tmpfs,destination=/tmpmount,size=78987"
			}`,
			"/tmpmount",
			78987,
		},
	}
	for _, testcase := range testCases {
		t.Run(testcase.testName, func(t *testing.T) {
			spec := &LaunchSpec{}
			if err := spec.UnmarshalJSON([]byte(testcase.mdsJSON)); err != nil {
				t.Errorf("got %v error, but expected nil error", err)
			}
		})
	}
}

func TestLaunchSpecUnmarshalJSONWithBadMounts(t *testing.T) {
	var testCases = []struct {
		testName string
		mdsJSON  string
		errMatch string
	}{
		{
			"Unknown Type",
			`{
				"tee-image-reference":"docker.io/library/hello-world:latest",
				"tee-mount":"type=hallo"
			}`,
			"found unknown or unspecified mount type",
		},
		{
			"Not k=v",
			`{
				"tee-image-reference":"docker.io/library/hello-world:latest",
				"tee-mount":"type=tmpfs,source"
			}`,
			"failed to parse mount option",
		},
		{
			"Unknown Option",
			`{
				"tee-image-reference":"docker.io/library/hello-world:latest",
				"tee-mount":"type=tmpfs,source=tmpfs,destination=/tmpmount,size=123,foo=bar"
			}`,
			"found unknown mount option",
		},
		{
			"Tmpfs Bad Source",
			`{
				"tee-image-reference":"docker.io/library/hello-world:latest",
				"tee-mount":"type=tmpfs,source=src,destination=/tmpmount"
			}`,
			"received wrong mount source",
		},
		{
			"Tmpfs No Destination",
			`{
				"tee-image-reference":"docker.io/library/hello-world:latest",
				"tee-mount":"type=tmpfs,source=tmpfs"
			}`,
			"mount type \"tmpfs\" must have destination specified",
		},
		{
			"Tmpfs Size Not Int",
			`{
					"tee-image-reference":"docker.io/library/hello-world:latest",
					"tee-mount":"type=tmpfs,source=tmpfs,destination=/tmpmount,size=foo"
			}`,
			"failed to convert size option",
		},
	}
	for _, testcase := range testCases {
		t.Run(testcase.testName, func(t *testing.T) {
			spec := &LaunchSpec{}
			spec.Experiments = experiments.Experiments{
				EnableTempFSMount: true,
			}
			err := spec.UnmarshalJSON([]byte(testcase.mdsJSON))
			if match, _ := regexp.MatchString(testcase.errMatch, err.Error()); !match {
				t.Errorf("got %v error, but expected %v error", err, testcase.errMatch)
			}
		})
	}
}
