package gpu

import (
	"fmt"
	"os"
	"path/filepath"
)

// FindBuiltInInstallationDir returns the only driver version directory under
// rootDir. It fails if rootDir has no subdirectory or more than one, so the
// launcher never picks a driver version silently.
func FindBuiltInInstallationDir(rootDir string) (string, error) {
	entries, err := os.ReadDir(rootDir)
	if err != nil {
		return "", fmt.Errorf("failed to read %s: %w", rootDir, err)
	}
	var dirs []string
	for _, entry := range entries {
		if entry.IsDir() {
			dirs = append(dirs, filepath.Join(rootDir, entry.Name()))
		}
	}
	if len(dirs) != 1 {
		return "", fmt.Errorf("want exactly one driver directory in %s, found %d: %v", rootDir, len(dirs), dirs)
	}
	return dirs[0], nil
}
