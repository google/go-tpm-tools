package gpu

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFindBuiltInInstallationDir(t *testing.T) {
	testCases := []struct {
		name    string
		dirs    []string
		files   []string
		want    string
		wantErr bool
	}{
		{
			name: "OneVersion",
			dirs: []string{"620.06"},
			want: "620.06",
		},
		{
			name:  "OneVersionAndFiles",
			dirs:  []string{"620.06"},
			files: []string{"README"},
			want:  "620.06",
		},
		{
			name:    "NoVersion",
			wantErr: true,
		},
		{
			name:    "TwoVersions",
			dirs:    []string{"610.57.04", "620.06"},
			wantErr: true,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			for _, d := range tc.dirs {
				if err := os.Mkdir(filepath.Join(root, d), 0755); err != nil {
					t.Fatal(err)
				}
			}
			for _, f := range tc.files {
				if err := os.WriteFile(filepath.Join(root, f), nil, 0644); err != nil {
					t.Fatal(err)
				}
			}

			got, err := FindBuiltInInstallationDir(root)
			if (err != nil) != tc.wantErr {
				t.Fatalf("FindBuiltInInstallationDir() error = %v, wantErr %v", err, tc.wantErr)
			}
			if !tc.wantErr && got != filepath.Join(root, tc.want) {
				t.Errorf("FindBuiltInInstallationDir() = %q, want %q", got, filepath.Join(root, tc.want))
			}
		})
	}

	t.Run("MissingRoot", func(t *testing.T) {
		if _, err := FindBuiltInInstallationDir(filepath.Join(t.TempDir(), "missing")); err == nil {
			t.Error("FindBuiltInInstallationDir() on a missing directory succeeded, want error")
		}
	})
}
