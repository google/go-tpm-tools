package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"google.golang.org/api/option"
	"google.golang.org/api/option/internaloption"
	htransport "google.golang.org/api/transport/http"
)

const (
	iamCredentialsURL   = "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/"
	accessTokenEndpoint = ":generateAccessToken"
	idTokenEndpoint     = ":generateIdToken"
)

type accessTokenReq struct {
	Delegates []string `json:"delegates,omitempty"`
	Scopes    []string `json:"scope,omitempty"`
}

type accessTokenResp struct {
	AccessToken string `json:"accessToken"`
	ExpireTime  string `json:"expireTime"`
}

type idTokenReq struct {
	Audience     string   `json:"audience"`
	IncludeEmail bool     `json:"includeEmail"`
	Delegates    []string `json:"delegates,omitempty"`
}

type idTokenResp struct {
	Token string `json:"token"`
}

type impersonatedTokenFetcher struct {
	client *http.Client
	// serviceAccounts []string
}

func newImpersonatedTokenFetcher(ctx context.Context, opts ...option.ClientOption) (*impersonatedTokenFetcher, error) {
	// if len(serviceAccounts) == 0 {
	// 	return nil, fmt.Errorf("no service accounts provided.")
	// }

	opts = append(opts, internaloption.WithDefaultAudience("https://iamcredentials.googleapis.com/"))
	client, _, err := htransport.NewClient(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("error creating client: %v", err)
	}

	return &impersonatedTokenFetcher{
		client: client,
		// serviceAccounts: serviceAccounts,
	}, nil
}

func (f *impersonatedTokenFetcher) postHTTP(url, authToken string, reqBody []byte) ([]byte, error) {
	req, err := http.NewRequest("POST", url, bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("unable to create HTTP request: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")
	if len(authToken) != 0 {
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", authToken))
	}

	resp, err := f.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP call returned error: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		fmt.Println(resp)
		return nil, fmt.Errorf("HTTP call returned non-OK status: %v", resp.Status)
	}

	defer resp.Body.Close()
	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("unable to read response body: %v", err)
	}

	return respBody, nil
}

func (f *impersonatedTokenFetcher) fetchAccessToken(serviceAccount, authToken string, delegates []string) (string, error) {
	url := iamCredentialsURL + serviceAccount + accessTokenEndpoint

	reqBody, err := json.Marshal(accessTokenReq{
		Delegates: delegates,
		Scopes:    []string{"https://www.googleapis.com/auth/cloud-platform"},
	})
	if err != nil {
		return "", fmt.Errorf("unable to marshal request body: %v", err)
	}

	respBody, err := f.postHTTP(url, authToken, reqBody)
	if err != nil {
		return "", fmt.Errorf("token retrieval failed: %v", err)
	}

	var response accessTokenResp
	if err = json.Unmarshal(respBody, &response); err != nil {
		return "", fmt.Errorf("unable to unmarshal response: %v", err)
	}

	return response.AccessToken, nil
}

func (f *impersonatedTokenFetcher) fetchIDToken(serviceAccount, authToken, audience string) (string, error) {
	url := iamCredentialsURL + serviceAccount + idTokenEndpoint

	reqBody, err := json.Marshal(idTokenReq{Audience: audience, IncludeEmail: true})
	if err != nil {
		return "", fmt.Errorf("unable to marshal request body: %v", err)
	}

	respBody, err := f.postHTTP(url, authToken, reqBody)
	if err != nil {
		return "", fmt.Errorf("token retrieval failed: %v", err)
	}

	var response idTokenResp
	if err = json.Unmarshal(respBody, &response); err != nil {
		return "", fmt.Errorf("unable to unmarshal response: %v", err)
	}

	return response.Token, nil
}

// Given a chain of delegate service accounts, returns an ID token for the last service account.
func (f *impersonatedTokenFetcher) fetchIDTokenFromChain(serviceAccounts []string, audience string) (string, error) {
	if len(serviceAccounts) == 0 {
		return "", fmt.Errorf("no service accounts provided")
	}

	// Retrieve an ID token for the last account in the chain.
	// An access token is required for all other accounts in the delegation chain.
	idTokenAccount := serviceAccounts[len(serviceAccounts)-1]
	accessTokenAccounts := serviceAccounts[:len(serviceAccounts)-1]

	var authToken string
	for i, sa := range accessTokenAccounts {
		fmt.Printf("Retrieving access token for delegate in position %v\n", i)

		var err error
		authToken, err = f.fetchAccessToken(sa, authToken, serviceAccounts[i+1:])
		if err != nil {
			return "", fmt.Errorf("unable to get access token: %v", err)
		}
	}

	fmt.Println("Retrieving impersonated ID token")
	idToken, err := f.fetchIDToken(idTokenAccount, authToken, audience)
	if err != nil {
		return "", fmt.Errorf("error retrieving ID token: %v", err)
	}

	return idToken, nil
}
