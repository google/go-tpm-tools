package launchermount

import (
	"regexp"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/opencontainers/runtime-spec/specs-go"
)

func TestCreateTmpfsMountAndSpecsMount(t *testing.T) {
	var testCases = []struct {
		testName           string
		mountMap           map[string]string
		expectedTmpfs      TmpfsMount
		expectedSpecsMount specs.Mount
	}{
		{
			"Basic Tmpfs Mount",
			map[string]string{
				"type":        "tmpfs",
				"source":      "tmpfs",
				"destination": "/d",
			},
			TmpfsMount{Destination: "/d"},
			specs.Mount{Type: TypeTmpfs,
				Source:      TypeTmpfs,
				Destination: "/d",
				Options:     []string{"nosuid", "noexec", "nodev"},
			},
		},
		{
			"Tmpfs Mount with Size",
			map[string]string{
				"type":        "tmpfs",
				"source":      "tmpfs",
				"destination": "/my dest",
				"size":        "21342314",
			},
			TmpfsMount{Destination: "/my dest", Size: 21342314},
			specs.Mount{Type: TypeTmpfs,
				Source:      TypeTmpfs,
				Destination: "/my dest",
				Options:     []string{"nosuid", "noexec", "nodev", "size=21342314"},
			},
		},
		{
			"Tmpfs Mount with Relative Dst",
			map[string]string{
				"type":        "tmpfs",
				"source":      "tmpfs",
				"destination": "my dest",
				"size":        "21342314",
			},
			TmpfsMount{Destination: "/my dest", Size: 21342314},
			specs.Mount{Type: TypeTmpfs,
				Source:      TypeTmpfs,
				Destination: "/my dest",
				Options:     []string{"nosuid", "noexec", "nodev", "size=21342314"},
			},
		},
		{
			"Tmpfs Mount with Relative Dst More Complex Filepath",
			map[string]string{
				"type":        "tmpfs",
				"source":      "tmpfs",
				"destination": "grandparent dir/parentDir/my dest",
			},
			TmpfsMount{Destination: "/grandparent dir/parentDir/my dest"},
			specs.Mount{Type: TypeTmpfs,
				Source:      TypeTmpfs,
				Destination: "/grandparent dir/parentDir/my dest",
				Options:     []string{"nosuid", "noexec", "nodev"},
			},
		},
		{
			"Tmpfs Mount with Dst Internal Rel Parent",
			map[string]string{
				"type":        "tmpfs",
				"source":      "tmpfs",
				"destination": "grandparent dir/parentDir/../../my dest",
			},
			TmpfsMount{Destination: "/my dest"},
			specs.Mount{Type: TypeTmpfs,
				Source:      TypeTmpfs,
				Destination: "/my dest",
				Options:     []string{"nosuid", "noexec", "nodev"},
			},
		},
		{
			"Tmpfs Mount with Relative Dst Internal Cwd",
			map[string]string{
				"type":        "tmpfs",
				"source":      "tmpfs",
				"destination": "grandparent dir/parentDir/.././my dest",
			},
			TmpfsMount{Destination: "/grandparent dir/my dest"},
			specs.Mount{Type: TypeTmpfs,
				Source:      TypeTmpfs,
				Destination: "/grandparent dir/my dest",
				Options:     []string{"nosuid", "noexec", "nodev"},
			},
		},
		{
			"Tmpfs Mount with Malformed Relative Dst",
			map[string]string{
				"type":        "tmpfs",
				"source":      "tmpfs",
				"destination": "grandparent dir/parentDir/.../.../my dest",
			},
			TmpfsMount{Destination: "/grandparent dir/parentDir/.../.../my dest"},
			specs.Mount{Type: TypeTmpfs,
				Source:      TypeTmpfs,
				Destination: "/grandparent dir/parentDir/.../.../my dest",
				Options:     []string{"nosuid", "noexec", "nodev"},
			},
		},
		{
			"Tmpfs Mount with Parent Relative Dst",
			map[string]string{
				"type":        "tmpfs",
				"source":      "tmpfs",
				"destination": "../my dest",
			},
			TmpfsMount{Destination: "/my dest"},
			specs.Mount{Type: TypeTmpfs,
				Source:      TypeTmpfs,
				Destination: "/my dest",
				Options:     []string{"nosuid", "noexec", "nodev"},
			},
		},
		{
			"Tmpfs Mount with Grandparent Relative Dst",
			map[string]string{
				"type":        "tmpfs",
				"source":      "tmpfs",
				"destination": "../../my dest",
			},
			TmpfsMount{Destination: "/my dest"},
			specs.Mount{Type: TypeTmpfs,
				Source:      TypeTmpfs,
				Destination: "/my dest",
				Options:     []string{"nosuid", "noexec", "nodev"},
			},
		},
	}
	for _, testcase := range testCases {
		t.Run(testcase.testName, func(t *testing.T) {
			mnt, err := CreateTmpfsMount(testcase.mountMap)
			if err != nil {
				t.Errorf("got non-nil error %v, want nil error", err)
			}
			if diff := cmp.Diff(mnt, testcase.expectedTmpfs); diff != "" {
				t.Errorf("got %v, want %v:\ndiff: %v", mnt, testcase.expectedTmpfs, diff)
			}
			spMnt := mnt.SpecsMount()
			if diff := cmp.Diff(spMnt, testcase.expectedSpecsMount); diff != "" {
				t.Errorf("got %v, want %v:\ndiff: %v", spMnt, testcase.expectedSpecsMount, diff)
			}
		})
	}
}

func TestCreateTmpfsMountFail(t *testing.T) {
	var testCases = []struct {
		testName string
		mountMap map[string]string
		wantErr  string
	}{
		{
			"Bad Mount Type",
			map[string]string{
				"type": "tfs",
			},
			"received wrong mount type",
		},
		{
			"Bad Mount Src",
			map[string]string{
				"type":   "tmpfs",
				"source": "tfffffs",
			},
			"received wrong mount source",
		},
		{
			"No Dest",
			map[string]string{
				"type":   "tmpfs",
				"source": "tmpfs",
			},
			errTmpfsMustHaveDest.Error(),
		},
		{
			"Bad Size",
			map[string]string{
				"type":        "tmpfs",
				"source":      "tmpfs",
				"destination": "dst",
				"size":        "notanum",
			},
			"failed to convert size option",
		},
		{
			"Unknown Opts",
			map[string]string{
				"type":        "tmpfs",
				"source":      "tmpfs",
				"destination": "dst",
				"size":        "111",
				"rw":          "true",
			},
			"received unknown mount options for tmpfs mount",
		},
	}
	for _, testcase := range testCases {
		t.Run(testcase.testName, func(t *testing.T) {
			if _, err := CreateTmpfsMount(testcase.mountMap); err == nil {
				t.Errorf("got nil error, want non-nil error \"%v\"", testcase.wantErr)
			} else {
				if match, _ := regexp.MatchString(testcase.wantErr, err.Error()); !match {
					t.Errorf("got error \"%v\", but expected \"%v\"", err, testcase.wantErr)
				}
			}
		})
	}
}
