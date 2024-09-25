package launcher

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

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

func TestListFilesWithPrefix(t *testing.T) {

	tmpDir := t.TempDir()
	file1 := filepath.Join(tmpDir, "file1.txt")
	file2 := filepath.Join(tmpDir, "file2.txt")

	var testCases = []struct {
		dir     string
		pattern string
		want    []string
		wantErr bool
	}{
		{
			dir:     tmpDir,
			pattern: "file",
			want:    []string{file1, file2},
			wantErr: false,
		},
		{
			dir:     tmpDir,
			pattern: "newfile",
			want:    []string{},
			wantErr: false,
		},
		{
			dir:     "otherdir",
			pattern: "file",
			want:    nil,
			wantErr: true,
		},
		{
			dir:     "otherdir",
			pattern: "tmpfile",
			want:    nil,
			wantErr: true,
		},
	}

	// Create test files
	os.WriteFile(file1, []byte("File 1 content"), 0644)
	os.WriteFile(file2, []byte("File 2 content"), 0644)

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("Dir: %s, Pattern: %s", tc.dir, tc.pattern), func(t *testing.T) {
			got, err := listFilesWithPrefix(tc.dir, tc.pattern)
			if (err != nil) != tc.wantErr {
				t.Errorf("listFilesWithPrefix(%s, %s): got error: %v, want error: %v", tc.dir, tc.pattern, err, tc.wantErr)
				return
			}
			if !tc.wantErr && !reflect.DeepEqual(got, tc.want) {
				t.Errorf("listFilesWithPrefix(%s, %s): got: %v, want: %v", tc.dir, tc.pattern, got, tc.want)
			}
		})
	}
}
