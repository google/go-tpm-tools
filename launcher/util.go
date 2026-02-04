package launcher

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/go-tpm/legacy/tpm2"
	"google.golang.org/api/impersonate"
	"google.golang.org/api/option"
)

// TPMDAParams holds TPM Dictionary Attack parameters.
type TPMDAParams struct {
	LockoutCounter      uint32
	MaxTries            uint32 // aka "MaxAuthFail" in TPM Properties
	RecoveryTime        uint32 // aka "LockoutInterval" in TPM Properties
	LockoutRecovery     uint32 // aka "LockoutRecovery" in TPM Properties
	StartupClearOrderly bool
}

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

// SetTPMDAParams takes in a TPM and updates its Dictionary Attack parameters
// Only MaxAuthFail, LockoutInterval and LockoutRecovery of TPMDAParams are
// used in this function.
func SetTPMDAParams(tpm io.ReadWriter, daParams TPMDAParams) error {
	// empty auth
	auth := tpm2.AuthCommand{
		Session:    tpm2.HandlePasswordSession,
		Attributes: tpm2.AttrContinueSession,
		Auth:       []byte(""),
	}
	return tpm2.DictionaryAttackParameters(tpm, auth, daParams.MaxTries, daParams.RecoveryTime, daParams.LockoutRecovery)
}

// GetTPMDAInfo takes in a TPM and read its Dictionary Attack parameters
func GetTPMDAInfo(tpm io.ReadWriter) (*TPMDAParams, error) {
	var tpmDAParams TPMDAParams

	lockoutCounter, err := getCapabilityProperty(tpm, tpm2.LockoutCounter) // 526
	if err != nil {
		return nil, err
	}
	tpmDAParams.LockoutCounter = lockoutCounter.Value

	maxAuthFail, err := getCapabilityProperty(tpm, tpm2.MaxAuthFail) // 527
	if err != nil {
		return nil, err
	}
	tpmDAParams.MaxTries = maxAuthFail.Value

	lockoutInterval, err := getCapabilityProperty(tpm, tpm2.LockoutInterval) // 528
	if err != nil {
		return nil, err
	}
	tpmDAParams.RecoveryTime = lockoutInterval.Value

	lockoutRecovery, err := getCapabilityProperty(tpm, tpm2.LockoutRecovery) // 529
	if err != nil {
		return nil, err
	}
	tpmDAParams.LockoutRecovery = lockoutRecovery.Value

	startUpClear, err := getCapabilityProperty(tpm, tpm2.TPMAStartupClear)
	if err != nil {
		return nil, err
	}
	// get the 31st bit (TPM-Rev-2.0-Part-2-Structures-01.38.pdf, Page 73)
	tpmDAParams.StartupClearOrderly = (startUpClear.Value&(1<<31)>>31 == 1)

	return &tpmDAParams, nil
}

func getCapabilityProperty(tpm io.ReadWriter, property tpm2.TPMProp) (*tpm2.TaggedProperty, error) {
	vals, _, err := tpm2.GetCapability(tpm, tpm2.CapabilityTPMProperties, 1, uint32(property))
	if err != nil {
		return nil, err
	}
	val, ok := vals[0].(tpm2.TaggedProperty)
	if !ok {
		return nil, fmt.Errorf("failed to cast returned value to tpm2.TaggedProperty: %v", val)
	}
	if val.Tag != property {
		return nil, fmt.Errorf("failed to get expected property from the TPM, want: %v, got: %v", property, val)
	}
	return &val, nil
}

func listFilesWithPrefix(targetDir string, prefix string) ([]string, error) {
	var targetFiles []string
	err := filepath.WalkDir(targetDir, func(path string, d os.DirEntry, err error) error {
		if err != nil && d != nil && d.IsDir() {
			return filepath.SkipDir
		}
		if d != nil && !d.IsDir() && strings.HasPrefix(filepath.Base(path), prefix) {
			targetFiles = append(targetFiles, path)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("error walking directory: %v", err)
	}
	return targetFiles, nil
}
