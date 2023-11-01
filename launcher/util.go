package launcher

import (
	"context"
	"fmt"

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
