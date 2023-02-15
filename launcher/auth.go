package launcher

import (
	"encoding/json"
	"strings"

	"cloud.google.com/go/compute/metadata"
	"github.com/containerd/containerd/remotes"
	"github.com/containerd/containerd/remotes/docker"
	"golang.org/x/oauth2"
)

// RetrieveAuthToken takes in a metadata server client, and uses it to read the
// default service account token from a GCE VM and returns the token.
func RetrieveAuthToken(client *metadata.Client) (oauth2.Token, error) {
	data, err := client.Get("instance/service-accounts/default/token")
	if err != nil {
		return oauth2.Token{}, err
	}

	var token oauth2.Token
	if err := json.Unmarshal([]byte(data), &token); err != nil {
		return oauth2.Token{}, err
	}

	return token, nil
}

// Resolver returns a custom resolver that can use the token to authenticate with
// the repo.
func Resolver(token string) remotes.Resolver {
	options := docker.ResolverOptions{}

	credentials := func(host string) (string, string, error) {
		// append the token if is talking to Artifact Registry or GCR Registry
		if strings.HasSuffix(host, "docker.pkg.dev") || strings.HasSuffix(host, "gcr.io") {
			return "_token", token, nil
		}
		return "", "", nil
	}
	authOpts := []docker.AuthorizerOpt{docker.WithAuthCreds(credentials)}
	options.Authorizer = docker.NewDockerAuthorizer(authOpts...)

	return docker.NewResolver(options)
}
