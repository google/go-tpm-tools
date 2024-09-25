package launcher

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"google.golang.org/api/impersonate"
	"google.golang.org/api/option"
)

// FetchImpersonatedToken return an access token for the impersonated service account.
func FetchImpersonatedToken(ctx context.Context, serviceAccount string, audience string, opts ...option.ClientOption) ([]byte, error) {
	config := impersonate.IDTokenConfig{
		Audience:        audience,
		TargetPrincipal: serviceAccount,
		IncludeEmail:    true,
	}

	tokenSource, err := impersonate.IDTokenSource(ctx, config, opts...)
	if err != nil {
		return nil, fmt.Errorf("error creating token source: %v", err)
	}

	token, err := tokenSource.Token()
	if err != nil {
		return nil, fmt.Errorf("error retrieving token: %v", err)
	}

	return []byte(token.AccessToken), nil
}

func listFilesWithPrefix(targetDir string, prefix string) ([]string, error) {
	targetFiles := make([]string, 0)

	err := filepath.WalkDir(targetDir, func(path string, _ os.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if strings.HasPrefix(filepath.Base(path), prefix) {
			targetFiles = append(targetFiles, path)
		}

		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("error walking directory: %v", err)
	}

	return targetFiles, nil
}
