// Package experiments contains functionalities to retrieve synced experiments
package experiments

import (
	"encoding/json"
	"fmt"
	"os"
)

// Experiments contains the experiments flags this version of the launcher expects to receive.
// Failure to unmarshal the experiment JSON data will result in an empty object being returned
// to treat experiment flags as their default value. The error should still be checked.
type Experiments struct {
	EnableTestFeatureForImage  bool
	EnableSignedContainerImage bool
}

// New takes a filepath, opens the file, and calls ReadJsonInput with the contents
// of the file.
// If the file cannot be opened, the experiments map is set to an empty map.
func New(fpath string) (Experiments, error) {
	f, err := os.ReadFile(fpath)
	if err != nil {
		// Return default values on failure.
		return Experiments{}, err
	}

	r, err := readJSONInput(f)

	return r, err
}

// ReadJSONInput  takes a reader and unmarshals the contents into the experiments map.
// If the unmarsahlling fails, the experiments map is set to an empty map.
func readJSONInput(b []byte) (Experiments, error) {
	var experiments Experiments
	if err := json.Unmarshal(b, &experiments); err != nil {
		// Return default values on failure.
		return Experiments{}, fmt.Errorf("failed to unmarshal json: %w", err)
	}
	return experiments, nil
}
