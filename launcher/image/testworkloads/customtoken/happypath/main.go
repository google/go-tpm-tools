// package main is a binary that will print out the validation status of a custom attestation token.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

const (
	socketPath = "/run/container_launcher/teeserver.sock"
)

func getCustomTokenBytes(body string) ([]byte, error) {
	httpClient := http.Client{
		Transport: &http.Transport{
			// Set the DialContext field to a function that creates
			// a new network connection to a Unix domain socket
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", socketPath)
			},
		},
	}

	// Get the token from the IPC endpoint
	url := "http://localhost/v1/token"

	resp, err := httpClient.Post(url, "application/json", strings.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to get raw custom token response: %w", err)
	}
	tokenbytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read custom token body: %w", err)
	}
	resp.Body.Close()

	return tokenbytes, nil
}

func decodeAndValidateToken(tokenBytes []byte, keyFunc func(t *jwt.Token) (any, error)) (*jwt.Token, error) {
	var err error

	unverifiedClaims := &jwt.RegisteredClaims{}
	_, _, err = jwt.NewParser().ParseUnverified(string(tokenBytes), unverifiedClaims)
	if err != nil {
		return nil, fmt.Errorf("failed to parse claims: %v", err)
	}
	now := time.Now()
	// Add one second for buffer.
	nbf := unverifiedClaims.NotBefore.Time.Add(time.Second)
	diff := nbf.Sub(now)
	ten := 10 * time.Second
	// Sleep until nbf is valid or max 10 seconds.
	if diff > 0 {
		if diff < ten {
			time.Sleep(diff)
		} else {
			time.Sleep(ten)
		}
	}

	token, err := jwt.NewParser().Parse(string(tokenBytes), keyFunc)

	fmt.Printf("Token valid: %v", token.Valid)
	if token.Valid {
		return token, nil
	}
	if ve, ok := err.(*jwt.ValidationError); ok {
		if ve.Errors&jwt.ValidationErrorMalformed != 0 {
			return nil, fmt.Errorf("token format invalid. Please contact the Confidential Space team for assistance")
		}
		if ve.Errors&(jwt.ValidationErrorNotValidYet) != 0 {
			// If device time is not synchronized with the Attestation Service you may need to account for that here.
			return nil, errors.New("token is not active yet")
		}
		if ve.Errors&(jwt.ValidationErrorExpired) != 0 {
			return nil, fmt.Errorf("token is expired")
		}
		return nil, fmt.Errorf("unknown validation error: %v", err)
	}

	return nil, fmt.Errorf("couldn't handle this token or couldn't read a validation error: %v", err)
}

func getTestRSAPublicKey(token *jwt.Token) (any, error) {
	// Always return the same hardcoded public key.

	// Verify the signing method
	if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
		return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
	}

	const publicKeyPEM = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAjz/x1INhnRfOm2eE71YE
FByB9mDyyjyQJ4HN+Vha8vqvtjM9T5DaFguG3LGlA9sTKEz72VWPs0K5ftlcI+/G
cbF4J4wH+j4T9VTprvQ8WE+3r6Kd+gqmmTDX8H/lZQqf/EgqmZ8rXzUSaXEGttBE
ZKitCpgbucE47981dhEqdX7zPGJUIuKW5T+JcRVwZ2I5sZyqXV7cVX9x/Uo+i2B+
fWS+zQFz3qXN8oeEAHPthrFfCv82+TRaqIWX9BOzJWo6TkCh+kkRG4rMcWXQqE+Z
tsRwRDo362eMUQqsowckm5XAsLWbHUz/JwVJNPLqT5zeQn7ru0xlAhi0wcb31OAU
RwIDAQAB
-----END PUBLIC KEY-----`

	return jwt.ParseRSAPublicKeyFromPEM([]byte(publicKeyPEM))
}

func main() {
	// Format token request
	body := `{
        "audience": "<YOURAUDIENCE>",
        "nonces": ["thisIsAcustomNonce", "thisIsAMuchLongerCustomNonceWithPaddingFor74Bytes0000000000000000000000000"],
		"token_type": "OIDC"
    }`

	// The following code could be run in a Confidential Space workload container to generate a
	// custom attestation intended to be sent to a remote party for verification.
	tokenbytes, err := getCustomTokenBytes(body)
	if err != nil {
		fmt.Println(err)
		return
	}

	// Method to return a public key used for testing
	keyFunc := getTestRSAPublicKey

	// The following code could be run by a remote party (not necessarily in a
	// Confidential Space workload) in order to verify properties of the original
	// Confidential Space workload that generated the attestation.
	token, err := decodeAndValidateToken(tokenbytes, keyFunc)
	if err != nil {
		fmt.Println(err)
		return
	}

	claimsString, err := json.MarshalIndent(token.Claims, "", "  ")
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println(string(claimsString))
}
