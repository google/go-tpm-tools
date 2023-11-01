package teeserver

import (
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"testing"

	"github.com/google/go-tpm-tools/launcher/launcherfile"
)

func TestGetDefaultToken(t *testing.T) {
	tmpDir := t.TempDir()
	tmpToken := path.Join(tmpDir, launcherfile.AttestationVerifierTokenFilename)
	// An empty attestHandler is fine for now as it is not being used
	// in the handler.
	ah := attestHandler{defaultTokenFile: tmpToken, logger: log.Default()}

	req := httptest.NewRequest(http.MethodGet, "/v1/token", nil)
	w := httptest.NewRecorder()
	ah.getToken(w, req)
	_, err := io.ReadAll(w.Result().Body)
	if err != nil {
		t.Error(err)
	}

	// The token file doesn't exist yet, expect a 404
	if w.Code != http.StatusNotFound {
		t.Errorf("got return code: %d, want: %d", w.Code, http.StatusNotFound)
	}

	// create a fake test token file
	testTokenContent := "test token"
	os.WriteFile(tmpToken, []byte(testTokenContent), 0644)

	// retry calling the handler, and now it should return the token file content
	w = httptest.NewRecorder()
	ah.getToken(w, req)
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
}
