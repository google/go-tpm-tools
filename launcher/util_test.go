package launcher

import (
	"bytes"

	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm-tools/internal/test"
	"google.golang.org/api/option"
)

var expectedEmail = "test2@google.com"
var expectedToken = []byte("test_token")
var expectedURL = fmt.Sprintf(idTokenEndpoint, expectedEmail)

var testClient = &http.Client{
	Transport: &testRoundTripper{
		roundTripFunc: func(req *http.Request) *http.Response {
			if req.URL.String() != expectedURL {
				return &http.Response{
					StatusCode: http.StatusNotFound,
				}
			}
			resp := idTokenResp{
				Token: string(expectedToken),
			}
			respBody, err := json.Marshal(resp)
			if err != nil {
				return &http.Response{
					StatusCode: http.StatusInternalServerError,
				}
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       io.NopCloser(bytes.NewBuffer(respBody)),
			}
		},
	},
}

func TestTPMDAOps(t *testing.T) {
	rwc := test.GetTPM(t)
	defer client.CheckedClose(t, rwc)

	daInfo, err := GetTPMDAInfo(rwc)
	if err != nil {
		t.Fatal(err)
	}

	// default simualator TPM params
	expectedDaInfo := TPMDAParams{0, 3, 1000, 1000, true}
	if !cmp.Equal(*daInfo, expectedDaInfo) {
		t.Errorf("expected default DA parameters, got %+v, want %+v", daInfo, expectedDaInfo)
	}

	err = SetTPMDAParams(rwc, TPMDAParams{MaxTries: 123, RecoveryTime: 456, LockoutRecovery: 789})
	if err != nil {
		t.Fatal(err)
	}

	daInfo, err = GetTPMDAInfo(rwc)
	if err != nil {
		t.Fatal(err)
	}
	expectedDaInfo = TPMDAParams{0 /*LockoutCounter*/, 123 /*MaxTries*/, 456 /*RecoveryTime*/, 789 /*LockoutRecovery*/, true}
	if !cmp.Equal(*daInfo, expectedDaInfo) {
		t.Errorf("expected default DA parameters, got %+v, want %+v", daInfo, expectedDaInfo)
	}
}

func TestFetchImpersonatedToken(t *testing.T) {
	token, err := FetchImpersonatedToken(context.Background(), expectedEmail, "test_aud", option.WithHTTPClient(testClient))
	if err != nil {
		t.Fatalf("fetchImpersonatedToken returned error: %v", err)
	}

	if !bytes.Equal(token, expectedToken) {
		t.Errorf("fetchImpersonatedToken did not return expected token: got %v, want %v", token, expectedToken)
	}
}

func TestFetchImpersonatedTokenNilAud(t *testing.T) {
	_, err := FetchImpersonatedToken(context.Background(), expectedEmail, "", option.WithHTTPClient(testClient))
	if err == nil || !strings.Contains(err.Error(), "audience") {
		t.Fatalf("got %v error, want audience error", err)
	}
}

func TestFetchImpersonatedTokenBadEmail(t *testing.T) {
	_, err := FetchImpersonatedToken(context.Background(), "", "test_aud", option.WithHTTPClient(testClient))
	if err == nil || strings.Contains(err.Error(), "audience") {
		t.Fatalf("got %v error, want creating token source error", err)
	}
}

type testRoundTripper struct {
	roundTripFunc func(*http.Request) *http.Response
}

func (t *testRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return t.roundTripFunc(req), nil
}

type idTokenResp struct {
	Token string `json:"token"`
}
