package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"google.golang.org/api/idtoken"
	"google.golang.org/api/option"
)

type testRoundTripper struct {
	roundTripFunc func(*http.Request) *http.Response
}

func (t *testRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return t.roundTripFunc(req), nil
}

func TestPostHTTPAddsAuthorizationHeader(t *testing.T) {
	expectedAuthToken := "auth_token"
	expectedAuthHeader := fmt.Sprintf("Bearer %s", expectedAuthToken)

	roundTripHandler := func(req *http.Request) *http.Response {
		auth := req.Header.Get("Authorization")
		if auth != expectedAuthHeader {
			t.Errorf("Request did not contain expected authorization header: got %v, want %v", auth, expectedAuthHeader)
		}

		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
		}
	}

	fetcher := &impersonatedTokenFetcher{
		client: &http.Client{
			Transport: &testRoundTripper{roundTripFunc: roundTripHandler},
		},
	}

	_, err := fetcher.postHTTP("test.url.com", expectedAuthToken, []byte("request body"))
	if err != nil {
		t.Errorf("postHTTP returned error: %v", err)
	}
}

func TestGetAccessToken(t *testing.T) {
	serviceAccount := "test0@google.com"
	delegates := []string{
		"test1@google.com",
		"test2@google.com",
	}

	expectedToken := "test token"

	expectedURL := iamCredentialsURL + serviceAccount + accessTokenEndpoint
	roundTripHandler := func(req *http.Request) *http.Response {
		if req.URL.String() != expectedURL {
			t.Errorf("Access Token request does not have expected endpoint: got %v, want %v", req.URL.String(), expectedURL)
		}

		resp := accessTokenResp{
			AccessToken: expectedToken,
			ExpireTime:  time.Now().Format("%s"),
		}

		respBody, err := json.Marshal(resp)
		if err != nil {
			t.Fatalf("Unable to marshal HTTP response: %v", err)
		}

		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(bytes.NewBuffer(respBody)),
		}
	}

	fetcher := &impersonatedTokenFetcher{
		client: &http.Client{
			Transport: &testRoundTripper{roundTripFunc: roundTripHandler},
		},
	}

	token, err := fetcher.fetchAccessToken(serviceAccount, "", delegates)
	if err != nil {
		t.Fatalf("getAccessToken returned error: %v", err)
	}

	if token != expectedToken {
		t.Errorf("getAccessToken did not return expected token: got %v, want %v", token, expectedToken)
	}
}

func TestGetIDToken(t *testing.T) {
	serviceAccount := "test0@google.com"
	audience := "test_aud"

	expectedToken := "test token"

	expectedURL := iamCredentialsURL + serviceAccount + idTokenEndpoint
	roundTripHandler := func(req *http.Request) *http.Response {
		if req.URL.String() != expectedURL {
			t.Errorf("ID Token request does not have expected endpoint: got %v, want %v", req.URL.String(), expectedURL)
		}

		resp := idTokenResp{
			Token: expectedToken,
		}

		respBody, err := json.Marshal(resp)
		if err != nil {
			t.Fatalf("Unable to marshal HTTP response: %v", err)
		}

		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(bytes.NewBuffer(respBody)),
		}
	}

	fetcher := &impersonatedTokenFetcher{
		client: &http.Client{
			Transport: &testRoundTripper{roundTripFunc: roundTripHandler},
		},
	}

	token, err := fetcher.fetchIDToken(serviceAccount, "", audience)
	if err != nil {
		t.Fatalf("getIDToken returned error: %v", err)
	}

	if token != expectedToken {
		t.Errorf("getIDToken did not return expected token: got %v, want %v", token, expectedToken)
	}
}

func TestFetchImpersonatedToken(t *testing.T) {
	serviceAccounts := []string{
		"test0@google.com",
		"test1@google.com",
		"test2@google.com",
	}

	expectedTokens := make(map[string]string)
	for index, sa := range serviceAccounts {
		expectedTokens[sa] = fmt.Sprintf("Token %v", index)
	}

	handleIDToken := func(req *http.Request) *http.Response {
		sa := strings.TrimPrefix(strings.TrimSuffix(req.URL.String(), idTokenEndpoint), iamCredentialsURL)
		token, ok := expectedTokens[sa]
		if !ok {
			t.Fatalf("Unexpected service account: %v", sa)
		}

		resp := idTokenResp{
			Token: token,
		}

		respBody, err := json.Marshal(resp)
		if err != nil {
			t.Fatalf("Unable to marshal HTTP response: %v", err)
		}

		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(bytes.NewBuffer(respBody)),
		}

	}

	handleAccessToken := func(req *http.Request) *http.Response {
		sa := strings.TrimPrefix(strings.TrimSuffix(req.URL.String(), accessTokenEndpoint), iamCredentialsURL)
		token, ok := expectedTokens[sa]
		if !ok {
			t.Fatalf("Unexpected service account: %v", sa)
		}

		resp := accessTokenResp{
			AccessToken: token,
			ExpireTime:  time.Now().Format("%s"),
		}

		respBody, err := json.Marshal(resp)
		if err != nil {
			t.Fatalf("Unable to marshal HTTP response: %v", err)
		}

		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(bytes.NewBuffer(respBody)),
		}
	}

	roundTripHandler := func(req *http.Request) *http.Response {
		if strings.HasSuffix(req.URL.Path, accessTokenEndpoint) {
			return handleAccessToken(req)
		}

		if strings.HasSuffix(req.URL.Path, idTokenEndpoint) {
			return handleIDToken(req)
		}

		t.Errorf("HTTP call was not made to a supported endpoint: %v", req.URL.String())
		return &http.Response{
			StatusCode: http.StatusNotFound,
			Header:     make(http.Header),
		}
	}

	fetcher := &impersonatedTokenFetcher{
		client: &http.Client{
			Transport: &testRoundTripper{roundTripFunc: roundTripHandler},
		},
	}

	token, err := fetcher.fetchIDTokenFromChain(serviceAccounts, "test_aud")
	if err != nil {
		t.Fatalf("fetchImpersonatedToken returned error: %v", err)
	}

	expectedToken := expectedTokens[serviceAccounts[len(serviceAccounts)-1]]
	if token != expectedToken {
		t.Errorf("fetchImpersonatedToken did not return expected token: got %v, want %v", token, expectedToken)
	}
}

func TestFetchImpersonatedTokenWithOneServiceAccount(t *testing.T) {
	serviceAccounts := []string{"test0@google.com"}
	expectedToken := "Token 0"

	roundTripHandler := func(req *http.Request) *http.Response {
		if !strings.HasSuffix(req.URL.Path, idTokenEndpoint) {
			t.Errorf("HTTP call was not made to ID token endpoint: %v", req.URL.String())
			return &http.Response{
				StatusCode: http.StatusNotFound,
				Header:     make(http.Header),
			}
		}

		resp := idTokenResp{
			Token: expectedToken,
		}

		respBody, err := json.Marshal(resp)
		if err != nil {
			t.Fatalf("Unable to marshal HTTP response: %v", err)
		}

		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(bytes.NewBuffer(respBody)),
		}
	}

	fetcher := &impersonatedTokenFetcher{
		client: &http.Client{
			Transport: &testRoundTripper{roundTripFunc: roundTripHandler},
		},
	}

	token, err := fetcher.fetchIDTokenFromChain(serviceAccounts, "test_aud")
	if err != nil {
		t.Fatalf("fetchImpersonatedToken returned error: %v", err)
	}

	if token != expectedToken {
		t.Errorf("fetchImpersonatedToken did not return expected token: got %v, want %v", token, expectedToken)
	}
}

func TestFetcherWithRealServiceAccounts(t *testing.T) {
	ctx := context.Background()

	serviceAccounts := []string{
		"impersonate1@jessieqliu-test.iam.gserviceaccount.com",
		"impersonate2@jessieqliu-test.iam.gserviceaccount.com",
		"impersonate3@jessieqliu-test.iam.gserviceaccount.com",
	}

	fetcher, err := newImpersonatedTokenFetcher(ctx)
	if err != nil {
		t.Fatalf("Creating fetcher failed: %v", err)
	}

	token, err := fetcher.fetchIDTokenFromChain(serviceAccounts, "test_aud")
	if err != nil {
		t.Fatalf("Fetching failed: %v", err)
	}

	validator, err := idtoken.NewValidator(ctx, option.WithoutAuthentication())
	if err != nil {
		t.Fatalf("Failed to create validator: %v", err)
	}

	payload, err := validator.Validate(ctx, token, "test_aud")
	if err != nil {
		t.Fatalf("Failed to validate token: %v", err)
	}

	email, ok := payload.Claims["email"]
	if !ok {
		t.Fatal("Token has no email claim.")
	}

	if email != serviceAccounts[len(serviceAccounts)-1] {
		t.Errorf("Token does not contain expected email: got %v, want %v", email, serviceAccounts[len(serviceAccounts)-1])
	}
}
