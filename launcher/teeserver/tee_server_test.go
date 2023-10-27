package teeserver

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"testing"

	"github.com/google/go-tpm-tools/launcher/launcherfile"
)

func TestGetDefaultToken(t *testing.T) {
	// An empty attestHandler is fine for now as it is not being used
	// in the handler.
	ah := attestHandler{}

	// delete any existing token in the test env
	tokenPath := path.Join(launcherfile.HostTmpPath, launcherfile.AttestationVerifierTokenFilename)
	os.Remove(tokenPath)

	req := httptest.NewRequest(http.MethodGet, "/v1/defaultToken", nil)
	w := httptest.NewRecorder()
	ah.getDefaultToken(w, req)
	_, err := io.ReadAll(w.Result().Body)
	if err != nil {
		t.Error(err)
	}

	// The token file doesn't exist yet, expect a 404
	if w.Code != http.StatusNotFound {
		t.Errorf("got return code: %d, want: %d", w.Code, http.StatusNotFound)
	}

	// create a fake test token file
	if _, err := os.Stat(launcherfile.HostTmpPath); os.IsNotExist(err) {
		if err := os.MkdirAll(launcherfile.HostTmpPath, 0755); err != nil {
			t.Fatalf("error creating host token path directory: %v", err)
		}
	}
	testTokenContent := "test token"
	os.WriteFile(tokenPath, []byte(testTokenContent), 0644)

	// retry calling the handler, and now it should return the token file content
	w = httptest.NewRecorder()
	ah.getDefaultToken(w, req)
	data, err := io.ReadAll(w.Result().Body)
	if err != nil {
		t.Error(err)
	}

	if w.Code != http.StatusOK {
		t.Errorf("got return code: %d, want: %d", w.Code, http.StatusOK)
	}
	if string(data) != testTokenContent {
		t.Errorf("got content: %v, want: %s", testTokenContent, string(data))
	}

	// Remove tmp testing files. Don't fail the test if it fails to delete the file.
	os.Remove(tokenPath)
	os.Remove(launcherfile.HostTmpPath)
}
