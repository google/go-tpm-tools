package spec

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestLaunchPolicy(t *testing.T) {
	testCases := []struct {
		testName       string
		imageLabels    map[string]string
		expectedPolicy LaunchPolicy
	}{
		{
			"single ENV override, CMD override",
			map[string]string{
				envOverride: "foo",
				cmdOverride: "true",
			},
			LaunchPolicy{
				AllowedEnvOverride: []string{"foo"},
				AllowedCmdOverride: true,
			},
		},
		{
			"multiple ENV override, no CMD override",
			map[string]string{
				envOverride: "foo,bar",
			},
			LaunchPolicy{
				AllowedEnvOverride: []string{"foo", "bar"},
				AllowedCmdOverride: false,
			},
		},
		{
			"no ENV override, no CMD override",
			nil,
			LaunchPolicy{
				AllowedEnvOverride: nil,
				AllowedCmdOverride: false,
			},
		},
		{
			"empty string in ENV override",
			map[string]string{
				envOverride: ",,,foo",
				cmdOverride: "false",
			},
			LaunchPolicy{
				AllowedEnvOverride: []string{"foo"},
				AllowedCmdOverride: false,
			},
		},
	}

	for _, testcase := range testCases {
		t.Run(testcase.testName, func(t *testing.T) {
			got, err := GetLaunchPolicy(testcase.imageLabels)
			if err != nil {
				t.Fatal(err)
			}

			if !cmp.Equal(got, testcase.expectedPolicy) {
				t.Errorf("Launchspec got %+v, want %+v", got, testcase.expectedPolicy)
			}
		})
	}
}

func TestVerify(t *testing.T) {
	testCases := []struct {
		testName  string
		policy    LaunchPolicy
		spec      LauncherSpec
		expectErr bool
	}{
		{
			"allow everything",
			LaunchPolicy{
				AllowedEnvOverride: []string{"foo"},
				AllowedCmdOverride: true,
			},
			LauncherSpec{
				Envs: []EnvVar{{Name: "foo", Value: "foo"}},
				Cmd:  []string{"foo"},
			},
			false,
		},
		{
			"default case",
			LaunchPolicy{},
			LauncherSpec{},
			false,
		},
		{
			"env override violation",
			LaunchPolicy{
				AllowedEnvOverride: []string{"foo"},
			},
			LauncherSpec{
				Envs: []EnvVar{{Name: "bar", Value: ""}},
			},
			true,
		},
		{
			"cmd violation",
			LaunchPolicy{
				AllowedCmdOverride: false,
			},
			LauncherSpec{
				Cmd: []string{"foo"},
			},
			true,
		},
		{
			"allow everything",
			LaunchPolicy{
				AllowedEnvOverride: []string{"foo"},
				AllowedCmdOverride: true,
			},
			LauncherSpec{
				Envs: []EnvVar{{Name: "foo", Value: "foo"}},
				Cmd:  []string{"foo"},
			},
			false,
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.testName, func(t *testing.T) {
			err := testCase.policy.Verify(testCase.spec)
			if testCase.expectErr {
				if err == nil {
					t.Errorf("expected error, but got nil")
				}
			} else {
				if err != nil {
					t.Errorf("expected no error, but got %v", err)
				}
			}
		})
	}
}
