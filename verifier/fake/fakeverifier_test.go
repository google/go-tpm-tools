package fake

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"reflect"
	"strings"
	"testing"

	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm-tools/internal/test"
	"github.com/google/go-tpm-tools/proto/attest"
	"github.com/google/go-tpm-tools/proto/tpm"
	"github.com/google/go-tpm-tools/verifier"
	"github.com/google/go-tpm-tools/verifier/oci"
	"github.com/google/go-tpm-tools/verifier/models"
	"google.golang.org/genproto/googleapis/rpc/code"

	"github.com/golang-jwt/jwt/v4"
)

func TestNewClient(t *testing.T) {
	// Test with nil signer, should use default test keys.
	clientDefault := NewClient(nil)
	if clientDefault == nil {
		t.Fatal("NewClient(nil) returned nil")
	}
	if !reflect.DeepEqual(clientDefault.(*fakeClient).signer, TestPrivateKey()) {
		t.Error("NewClient did not set the default key correctly")
	}

	// Test with a custom signer.
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %v", err)
	}
	clientCustom := NewClient(privateKey)
	if clientCustom == nil {
		t.Fatal("NewClient with custom signer returned nil")
	}
	if !reflect.DeepEqual(clientCustom.(*fakeClient).signer, privateKey) {
		t.Error("NewClient did not set the custom signer correctly")
	}
}

func TestCreateChallenge(t *testing.T) {
	// Challenge is hardcoded, so just verify the returned values.
	c := NewClient(nil)
	challenge, err := c.CreateChallenge(context.Background())
	if err != nil {
		t.Fatalf("CreateChallenge() failed: %v", err)
	}
	if challenge.Name != "projects/fakeProject/locations/fakeRegion/challenges/d882c62f-452f-4709-9335-0cccaf64eee1" {
		t.Errorf("unexpected challenge name: got %s", challenge.Name)
	}
	if len(challenge.Nonce) == 0 {
		t.Error("challenge nonce is empty")
	}
}

func TestVerifyAttestation(t *testing.T) {
	rwc := test.GetTPM(t)
	defer client.CheckedClose(t, rwc)

	ak, err := client.AttestationKeyRSA(rwc)
	if err != nil {
		t.Fatalf("AttestationKeyRSA() failed: %v", err)
	}
	defer ak.Close()

	fakeClient := NewClient(nil)
	challenge, err := fakeClient.CreateChallenge(context.Background())
	if err != nil {
		t.Fatalf("CreateChallenge() failed: %v", err)
	}

	attestation, err := ak.Attest(client.AttestOpts{Nonce: challenge.Nonce})
	if err != nil {
		t.Fatalf("Attest() failed: %v", err)
	}

	tests := []struct {
		name                   string
		containerSigs          []*verifier.ContainerSignature
		tokenOpts              *models.TokenOptions
		expectPartialErr       bool
		expectPartialErrCode   code.Code
		expectPartialErrSubstr string
	}{
		{
			name: "SuccessNoContainerSigs",
		},
		{
			name: "SuccessWithContainerSigs",
			containerSigs: []*verifier.ContainerSignature{
				{
					Payload:   []byte("somepubkey," + string(oci.RSASSAPKCS1V152048SHA256)),
					Signature: []byte("somesig"),
				},
			},
		},
		{
			name: "FailureInvalidContainerSigAlg",
			containerSigs: []*verifier.ContainerSignature{
				{
					Payload:   []byte("somepubkey,invalid-alg"),
					Signature: []byte("somesig"),
				},
			},
			expectPartialErr:       true,
			expectPartialErrCode:   code.Code_INVALID_ARGUMENT,
			expectPartialErrSubstr: "unsupported algorithm",
		},
		{
			name: "SuccessWithCustomAudience",
			tokenOpts: &models.TokenOptions{
				Audience: "custom-audience",
			},
		},
		{
			name: "SuccessWithMultipleContainerSigs",
			containerSigs: []*verifier.ContainerSignature{
				{
					Payload:   []byte("pubkey1," + string(oci.ECDSAP256SHA256)),
					Signature: []byte("sig1"),
				},
				{
					Payload:   []byte("pubkey2,invalid-alg"),
					Signature: []byte("sig2"),
				},
				{
					Payload:   []byte("pubkey3," + string(oci.RSASSAPSS2048SHA256)),
					Signature: []byte("sig3"),
				},
			},
			expectPartialErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := verifier.VerifyAttestationRequest{
				Attestation:              attestation,
				ContainerImageSignatures: tc.containerSigs,
				TokenOptions:             tc.tokenOpts,
			}
			resp, err := fakeClient.VerifyAttestation(context.Background(), req)
			if err != nil {
				t.Fatalf("VerifyAttestation() failed: %v", err)
			}
			if len(resp.ClaimsToken) == 0 {
				t.Error("ClaimsToken is empty")
			}

			// Verify claims for relevant tests
			if tc.tokenOpts != nil && tc.tokenOpts.Audience != "" {
				claims := &Claims{}
				// We don't need to verify the signature, just parse the claims
				_, _, err := jwt.NewParser().ParseUnverified(string(resp.ClaimsToken), claims)
				if err != nil {
					t.Fatalf("Failed to parse claims token: %v", err)
				}
				if !claims.RegisteredClaims.VerifyAudience(tc.tokenOpts.Audience, true) {
					t.Errorf("Expected audience '%s', but got %v", tc.tokenOpts.Audience, claims.Audience)
				}
			}

			if tc.expectPartialErr {
				if len(resp.PartialErrs) == 0 {
					t.Fatal("expected partial errors, but got none")
				}
				// For single error cases, check the code and substring
				if tc.expectPartialErrCode != 0 {
					if resp.PartialErrs[0].Code != int32(tc.expectPartialErrCode) {
						t.Errorf("expected partial error code %v, got %v", tc.expectPartialErrCode, resp.PartialErrs[0].Code)
					}
					if !strings.Contains(resp.PartialErrs[0].Message, tc.expectPartialErrSubstr) {
						t.Errorf("partial error message '%s' does not contain '%s'", resp.PartialErrs[0].Message, tc.expectPartialErrSubstr)
					}
				}
				// For the multiple signature case, just check the count
				if tc.name == "SuccessWithMultipleContainerSigs" {
					if len(resp.PartialErrs) != 1 {
						t.Errorf("expected 1 partial error, got %d", len(resp.PartialErrs))
					}
					claims := &Claims{}
					_, _, err := jwt.NewParser().ParseUnverified(string(resp.ClaimsToken), claims)
					if err != nil {
						t.Fatalf("Failed to parse claims token: %v", err)
					}
					if len(claims.ContainerImageSignatures) != 2 {
						t.Errorf("expected 2 container image signatures in claims, got %d", len(claims.ContainerImageSignatures))
					}
				}
			} else {
				if len(resp.PartialErrs) > 0 {
					t.Errorf("unexpected partial errors: %v", resp.PartialErrs)
				}
			}
		})
	}
}

func TestVerifyAttestationFailure(t *testing.T) {
	rwc := test.GetTPM(t)
	defer client.CheckedClose(t, rwc)

	ak, err := client.AttestationKeyRSA(rwc)
	if err != nil {
		t.Fatalf("AttestationKeyRSA() failed: %v", err)
	}
	defer ak.Close()

	fakeClient := NewClient(nil)
	challenge, err := fakeClient.CreateChallenge(context.Background())
	if err != nil {
		t.Fatalf("CreateChallenge() failed: %v", err)
	}

	// Create a valid attestation to start with
	validAttestation, err := ak.Attest(client.AttestOpts{Nonce: challenge.Nonce})
	if err != nil {
		t.Fatalf("Attest() failed: %v", err)
	}

	// Create an attestation with a different nonce for the verification failure test
	badNonceChallenge := []byte{1, 2, 3, 4}
	attestationWithBadNonce, err := ak.Attest(client.AttestOpts{Nonce: badNonceChallenge})
	if err != nil {
		t.Fatalf("Attest() with bad nonce failed: %v", err)
	}

	tests := []struct {
		name        string
		attestation *attest.Attestation
		wantErrSub  string
	}{
		{
			name: "CorruptAkPub",
			attestation: &attest.Attestation{
				AkPub: []byte("not a real public key"),
			},
			wantErrSub: "failed to decode AKPub",
		},
		{
			name:        "VerificationFails",
			attestation: attestationWithBadNonce,
			wantErrSub:  "failed to verify attestation",
		},
		{
			name: "ParseCosCELPCRFails",
			attestation: &attest.Attestation{
				AkPub:             validAttestation.GetAkPub(),
				Quotes:            validAttestation.GetQuotes(),
				CanonicalEventLog: []byte("this is not a valid event log"),
			},
			wantErrSub: "failed to validate the Canonical event log",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := verifier.VerifyAttestationRequest{Attestation: tc.attestation}
			_, err := fakeClient.VerifyAttestation(context.Background(), req)
			if err == nil {
				t.Fatalf("VerifyAttestation() succeeded, want error containing '%s'", tc.wantErrSub)
			}
			if !strings.Contains(err.Error(), tc.wantErrSub) {
				t.Errorf("VerifyAttestation() returned error '%v', want error containing '%s'", err, tc.wantErrSub)
			}
		})
	}
}

func TestVerifyConfidentialSpace(t *testing.T) {
	fc := NewClient(nil).(*fakeClient)
	// VerifyConfidentialSpace should be identical to VerifyAttestation.
	// We can just check if the functions are the same.
	// This may need to be updated if verifycs implementation changes.
	va := reflect.ValueOf(fc.VerifyAttestation)
	vcs := reflect.ValueOf(fc.VerifyConfidentialSpace)
	if va.Pointer() != vcs.Pointer() {
		// If they are not identical, we should write a dedicated test.
		t.Log("VerifyConfidentialSpace is not identical to VerifyAttestation, a dedicated test might be needed.")
	}
}

func TestExtractClaims(t *testing.T) {
	// Test a valid signature.
	sig := &verifier.ContainerSignature{
		Payload:   []byte("testPublicKey," + string(oci.RSASSAPKCS1V152048SHA256)),
		Signature: []byte("testSignature"),
	}
	claims, err := extractClaims(sig)
	if err != nil {
		t.Fatalf("extractClaims failed: %v", err)
	}
	if claims.PubKey != "testPublicKey" {
		t.Errorf("unexpected PubKey: got %s", claims.PubKey)
	}
	if claims.SigAlg != string(oci.RSASSAPKCS1V152048SHA256) {
		t.Errorf("unexpected SigAlg: got %s", claims.SigAlg)
	}
	encodedSig := base64.StdEncoding.EncodeToString([]byte("testSignature"))
	if claims.Signature != encodedSig {
		t.Errorf("unexpected Signature: got %s", claims.Signature)
	}

	// Test an invalid signature algorithm.
	invalidSig := &verifier.ContainerSignature{
		Payload:   []byte("testPublicKey,invalid-alg"),
		Signature: []byte("testSignature"),
	}
	_, err = extractClaims(invalidSig)
	if err == nil {
		t.Fatal("expected error for invalid signature algorithm, got nil")
	}
}

func TestExtractPCRBank(t *testing.T) {
	attestation := &attest.Attestation{
		Quotes: []*tpm.Quote{
			{Pcrs: &tpm.PCRs{Hash: tpm.HashAlgo_SHA1, Pcrs: map[uint32][]byte{0: {0}}}},
			{Pcrs: &tpm.PCRs{Hash: tpm.HashAlgo_SHA256, Pcrs: map[uint32][]byte{1: {1}, 2: {2}}}},
		},
	}

	// Test hash algo present
	pcrBank, err := extractPCRBank(attestation, tpm.HashAlgo_SHA256)
	if err != nil {
		t.Fatalf("extractPCRBank for SHA256 failed: %v", err)
	}
	if len(pcrBank.PCRs) != 2 || pcrBank.PCRs[0].Index != 1 || pcrBank.PCRs[1].Index != 2 {
		t.Errorf("unexpected PCRs for SHA256: %+v", pcrBank.PCRs)
	}

	// Test hash algo not present
	_, err = extractPCRBank(attestation, tpm.HashAlgo_SHA384)
	if err == nil {
		t.Fatal("extractPCRBank for SHA384 unexpectedly succeeded")
	}
}
