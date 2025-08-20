package server

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	_ "embed"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"strconv"
	"testing"

	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm-tools/internal"
	"github.com/google/go-tpm-tools/internal/test"
	attestpb "github.com/google/go-tpm-tools/proto/attest"
	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
	"github.com/google/logger"
	"google.golang.org/protobuf/proto"
)

func getDigestHash(input string) []byte {
	inputDigestHash := sha256.New()
	inputDigestHash.Write([]byte(input))
	return inputDigestHash.Sum(nil)
}

func extendPCRsRandomly(rwc io.ReadWriteCloser, selpcr tpm2.PCRSelection) error {
	var pcrExtendValue []byte
	if selpcr.Hash == tpm2.AlgSHA256 {
		pcrExtendValue = make([]byte, 32)
	} else if selpcr.Hash == tpm2.AlgSHA1 {
		pcrExtendValue = make([]byte, 20)
	}

	for _, v := range selpcr.PCRs {
		_, err := rand.Read(pcrExtendValue)
		if err != nil {
			return fmt.Errorf("random bytes read fail %v", err)
		}
		err = tpm2.PCRExtend(rwc, tpmutil.Handle(v), selpcr.Hash, pcrExtendValue, "")
		if err != nil {
			return fmt.Errorf("PCR extend fail %v", err)
		}
	}
	return nil
}

func TestMain(m *testing.M) {
	logger.Init("TestLog", false, false, os.Stderr)
	os.Exit(m.Run())
}

func TestVerifyHappyCases(t *testing.T) {
	rwc := test.GetTPM(t)
	defer client.CheckedClose(t, rwc)

	onePCR := []int{test.DebugPCR}
	twoPCR := append(onePCR, test.ApplicationPCR)
	dupePCR := append(twoPCR, twoPCR...)

	subtests := []struct {
		name         string
		getKey       func(io.ReadWriter) (*client.Key, error)
		pcrHashAlgo  tpm2.Algorithm
		quotePCRList []int
		extraData    []byte
	}{
		{"AK-RSA_SHA1_2PCRs_nonce", client.AttestationKeyRSA, tpm2.AlgSHA1, twoPCR, getDigestHash("test")},
		{"AK-RSA_SHA1_1PCR_nonce", client.AttestationKeyRSA, tpm2.AlgSHA1, onePCR, getDigestHash("t")},
		{"AK-RSA_SHA1_1PCR_no-nonce", client.AttestationKeyRSA, tpm2.AlgSHA1, onePCR, nil},
		{"AK-RSA_SHA256_2PCRs_nonce", client.AttestationKeyRSA, tpm2.AlgSHA256, twoPCR, getDigestHash("test")},
		{"AK-RSA_SHA256_2PCR_empty-nonce", client.AttestationKeyRSA, tpm2.AlgSHA256, twoPCR, []byte{}},
		{"AK-RSA_SHA256_dupePCrSel_nonce", client.AttestationKeyRSA, tpm2.AlgSHA256, dupePCR, getDigestHash("")},

		{"AK-ECC_SHA1_2PCRs_nonce", client.AttestationKeyECC, tpm2.AlgSHA1, twoPCR, getDigestHash("test")},
		{"AK-ECC_SHA1_1PCR_nonce", client.AttestationKeyECC, tpm2.AlgSHA1, onePCR, getDigestHash("t")},
		{"AK-ECC_SHA1_1PCR_no-nonce", client.AttestationKeyECC, tpm2.AlgSHA1, onePCR, nil},
		{"AK-ECC_SHA256_2PCRs_nonce", client.AttestationKeyECC, tpm2.AlgSHA256, twoPCR, getDigestHash("test")},
		{"AK-ECC_SHA256_2PCR_empty-nonce", client.AttestationKeyECC, tpm2.AlgSHA256, twoPCR, []byte{}},
		{"AK-ECC_SHA256_dupePCrSel_nonce", client.AttestationKeyECC, tpm2.AlgSHA256, dupePCR, getDigestHash("")},
	}
	for _, subtest := range subtests {
		t.Run(subtest.name, func(t *testing.T) {
			ak, err := subtest.getKey(rwc)
			if err != nil {
				t.Errorf("failed to generate AK: %v", err)
			}
			defer ak.Close()

			selpcr := tpm2.PCRSelection{
				Hash: subtest.pcrHashAlgo,
				PCRs: subtest.quotePCRList,
			}
			err = extendPCRsRandomly(rwc, selpcr)
			if err != nil {
				t.Fatalf("failed to extend test PCRs: %v", err)
			}
			quote, err := ak.Quote(selpcr, subtest.extraData)
			if err != nil {
				t.Fatalf("failed to quote: %v", err)
			}
			err = internal.VerifyQuote(quote, ak.PublicKey(), subtest.extraData)
			if err != nil {
				t.Fatalf("failed to verify: %v", err)
			}
		})
	}
}

func TestVerifyPCRChanged(t *testing.T) {
	rwc := test.GetTPM(t)
	defer client.CheckedClose(t, rwc)

	ak, err := client.AttestationKeyRSA(rwc)
	if err != nil {
		t.Errorf("failed to generate AK: %v", err)
	}
	defer ak.Close()

	selpcr := tpm2.PCRSelection{
		Hash: tpm2.AlgSHA256,
		PCRs: []int{test.DebugPCR},
	}
	err = extendPCRsRandomly(rwc, selpcr)
	if err != nil {
		t.Errorf("failed to extend test PCRs: %v", err)
	}
	nonce := getDigestHash("test")
	quote, err := ak.Quote(selpcr, nonce)
	if err != nil {
		t.Error(err)
	}

	// change the PCR value
	err = extendPCRsRandomly(rwc, selpcr)
	if err != nil {
		t.Errorf("failed to extend test PCRs: %v", err)
	}

	quote.Pcrs, err = client.ReadPCRs(rwc, selpcr)
	if err != nil {
		t.Errorf("failed to read PCRs: %v", err)
	}
	err = internal.VerifyQuote(quote, ak.PublicKey(), nonce)
	if err == nil {
		t.Errorf("Verify should fail as Verify read a modified PCR")
	}
}

func TestVerifyUsingDifferentPCR(t *testing.T) {
	rwc := test.GetTPM(t)
	defer client.CheckedClose(t, rwc)

	ak, err := client.AttestationKeyRSA(rwc)
	if err != nil {
		t.Errorf("failed to generate AK: %v", err)
	}
	defer ak.Close()

	err = extendPCRsRandomly(rwc, tpm2.PCRSelection{
		Hash: tpm2.AlgSHA256,
		PCRs: []int{test.DebugPCR, test.ApplicationPCR},
	})
	if err != nil {
		t.Errorf("failed to extend test PCRs: %v", err)
	}

	nonce := getDigestHash("test")
	quote, err := ak.Quote(tpm2.PCRSelection{
		Hash: tpm2.AlgSHA256,
		PCRs: []int{test.DebugPCR},
	}, nonce)
	if err != nil {
		t.Error(err)
	}

	quote.Pcrs, err = client.ReadPCRs(rwc, tpm2.PCRSelection{
		Hash: tpm2.AlgSHA256,
		PCRs: []int{test.ApplicationPCR},
	})
	if err != nil {
		t.Errorf("failed to read PCRs: %v", err)
	}
	err = internal.VerifyQuote(quote, ak.PublicKey(), nonce)
	if err == nil {
		t.Errorf("Verify should fail as Verify read a different PCR")
	}
}

func TestVerifyWithTrustedAK(t *testing.T) {
	rwc := test.GetTPM(t)
	defer client.CheckedClose(t, rwc)

	ak, err := client.AttestationKeyRSA(rwc)
	if err != nil {
		t.Fatalf("failed to generate AK: %v", err)
	}
	defer ak.Close()

	nonce := []byte("super secret nonce")
	attestation, err := ak.Attest(client.AttestOpts{Nonce: nonce})
	if err != nil {
		t.Fatalf("failed to attest: %v", err)
	}

	opts := VerifyOpts{
		Nonce:      nonce,
		TrustedAKs: []crypto.PublicKey{ak.PublicKey()},
	}
	_, err = VerifyAttestation(attestation, opts)
	if err != nil {
		t.Errorf("failed to verify: %v", err)
	}
}

func TestVerifyHashNonce(t *testing.T) {
	rwc := test.GetTPM(t)
	defer client.CheckedClose(t, rwc)

	ak, err := client.AttestationKeyRSA(rwc)
	if err != nil {
		t.Fatalf("failed to generate AK: %v", err)
	}
	defer ak.Close()
	tests := []struct {
		attHash bool
		verHash bool
		wantErr bool
	}{
		{true, true, false},
		{false, false, false},
		{true, false, true},
		{false, true, true},
	}
	nonce := []byte("super secret nonce")

	for _, test := range tests {
		t.Run("attest hash "+strconv.FormatBool(test.attHash)+" verify hash "+strconv.FormatBool(test.verHash), func(t *testing.T) {
			attestation, err := ak.Attest(client.AttestOpts{Nonce: nonce, HashNonce: test.attHash})
			if err != nil {
				t.Fatalf("failed to attest: %v", err)
			}

			opts := VerifyOpts{
				Nonce:      nonce,
				TrustedAKs: []crypto.PublicKey{ak.PublicKey()},
				HashNonce:  test.verHash,
			}
			_, err = VerifyAttestation(attestation, opts)
			if test.wantErr != (err != nil) {
				t.Errorf("Attest(HashNonce %v), Verify(HashNonce %v): got %v wantErr %v", test.attHash, test.verHash, err, test.wantErr)
			}
		})
	}
}

func TestVerifySHA1Attestation(t *testing.T) {
	rwc := test.GetTPM(t)
	defer client.CheckedClose(t, rwc)

	ak, err := client.AttestationKeyRSA(rwc)
	if err != nil {
		t.Fatalf("failed to generate AK: %v", err)
	}
	defer ak.Close()

	nonce := []byte("super secret nonce")
	attestation, err := ak.Attest(client.AttestOpts{Nonce: nonce})
	if err != nil {
		t.Fatalf("failed to attest: %v", err)
	}

	// We should get a SHA-256 state, even if we allow SHA-1
	opts := VerifyOpts{
		Nonce:      nonce,
		TrustedAKs: []crypto.PublicKey{ak.PublicKey()},
		AllowSHA1:  true,
	}
	state, err := VerifyAttestation(attestation, opts)
	if err != nil {
		t.Errorf("failed to verify: %v", err)
	}
	h := tpm2.Algorithm(state.GetHash())
	if h != tpm2.AlgSHA256 {
		t.Errorf("expected SHA-256 state, got: %v", h)
	}

	// Now we mess up the SHA-256 state to force SHA-1 fallback
	for _, quote := range attestation.GetQuotes() {
		if tpm2.Algorithm(quote.GetPcrs().GetHash()) == tpm2.AlgSHA256 {
			quote.Quote = nil
		}
	}
	state, err = VerifyAttestation(attestation, opts)
	if err != nil {
		t.Errorf("failed to verify: %v", err)
	}
	h = tpm2.Algorithm(state.GetHash())
	if h != tpm2.AlgSHA1 {
		t.Errorf("expected SHA-1 state, got: %v", h)
	}

	// SHA-1 fallback can then be disabled
	opts.AllowSHA1 = false
	if _, err = VerifyAttestation(attestation, opts); err == nil {
		t.Error("expected attestation to fail with only SHA-1")
	}
}

func TestVerifyAttestationWithCerts(t *testing.T) {
	tests := []struct {
		name        string
		attestation []byte
		nonce       []byte
	}{
		{
			"no-nonce",
			test.COS85NoNonce,
			nil,
		},
		{
			"nonce-9009",
			test.COS85Nonce9009,
			[]byte{0x90, 0x09},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			attestBytes := test.attestation
			att := &attestpb.Attestation{}
			if err := proto.Unmarshal(attestBytes, att); err != nil {
				t.Fatalf("failed to unmarshal attestation: %v", err)
			}

			if _, err := VerifyAttestation(att, VerifyOpts{
				Nonce:             test.nonce,
				TrustedRootCerts:  GceEKRoots,
				IntermediateCerts: GceEKIntermediates,
			}); err != nil {
				t.Errorf("failed to VerifyAttestation with AKCert: %v", err)
			}
		})
	}
}

func TestVerifyAutomaticallyUsesIntermediatesInAttestation(t *testing.T) {
	attestBytes := test.COS85Nonce9009
	att := &attestpb.Attestation{}
	if err := proto.Unmarshal(attestBytes, att); err != nil {
		t.Fatalf("failed to unmarshal attestation: %v", err)
	}
	att.IntermediateCerts = [][]byte{gceEKIntermediateCA2}

	if _, err := VerifyAttestation(att, VerifyOpts{
		Nonce:            []byte{0x90, 0x09},
		TrustedRootCerts: GceEKRoots,
	}); err != nil {
		t.Errorf("failed to VerifyAttestation with intermediates provided in attestation: %v", err)
	}
}

func TestVerifySucceedsWithOverlappingIntermediatesInOptionsAndAttestation(t *testing.T) {
	attestBytes := test.COS85Nonce9009
	att := &attestpb.Attestation{}
	if err := proto.Unmarshal(attestBytes, att); err != nil {
		t.Fatalf("failed to unmarshal attestation: %v", err)
	}
	att.IntermediateCerts = [][]byte{gceEKIntermediateCA2}

	if _, err := VerifyAttestation(att, VerifyOpts{
		Nonce:             []byte{0x90, 0x09},
		TrustedRootCerts:  GceEKRoots,
		IntermediateCerts: GceEKIntermediates,
	}); err != nil {
		t.Errorf("failed to VerifyAttestation with overlapping intermediates provided in attestation and options: %v", err)
	}
}

func TestValidateOptsFailWithCertsAndPubkey(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	opts := VerifyOpts{
		Nonce:             nil,
		TrustedRootCerts:  GceEKRoots,
		IntermediateCerts: GceEKIntermediates,
		TrustedAKs:        []crypto.PublicKey{priv.Public()},
	}
	if err := validateOpts(opts); err == nil {
		t.Error("Verified attestation even with multiple trust methods")
	}
}

func TestValidateAK(t *testing.T) {
	attestBytes := test.COS85NoNonce
	att := &attestpb.Attestation{}
	if err := proto.Unmarshal(attestBytes, att); err != nil {
		t.Fatalf("failed to unmarshal attestation: %v", err)
	}

	rwc := test.GetTPM(t)
	t.Cleanup(func() { client.CheckedClose(t, rwc) })

	ak, err := client.AttestationKeyRSA(rwc)
	if err != nil {
		t.Fatalf("failed to generate AK: %v", err)
	}
	t.Cleanup(ak.Close)

	testCases := []struct {
		name     string
		att      func() *attestpb.Attestation
		opts     VerifyOpts
		wantPass bool
	}{
		{
			name: "success with validateAKCert",
			att:  func() *attestpb.Attestation { return att },
			opts: VerifyOpts{
				TrustedRootCerts:  GceEKRoots,
				IntermediateCerts: GceEKIntermediates,
			},
			wantPass: true,
		},
		{
			name: "success with validateAKPub",
			att: func() *attestpb.Attestation {
				nonce := []byte("super secret nonce")
				attestation, err := ak.Attest(client.AttestOpts{Nonce: nonce})
				if err != nil {
					t.Fatalf("failed to attest: %v", err)
				}
				return attestation
			},
			opts:     VerifyOpts{TrustedAKs: []crypto.PublicKey{ak.PublicKey()}},
			wantPass: true,
		},
		{
			name: "failed with empty roots and intermediates",
			att:  func() *attestpb.Attestation { return att },
			opts: VerifyOpts{
				TrustedRootCerts:  nil,
				IntermediateCerts: nil,
			},
			wantPass: false,
		},
		{
			name:     "failed with empty VerifyOpts",
			att:      func() *attestpb.Attestation { return att },
			opts:     VerifyOpts{},
			wantPass: false,
		},
		{
			name:     "failed with missing roots",
			att:      func() *attestpb.Attestation { return att },
			opts:     VerifyOpts{IntermediateCerts: GceEKIntermediates},
			wantPass: false,
		},
		{
			name:     "failed with missing intermediates",
			att:      func() *attestpb.Attestation { return att },
			opts:     VerifyOpts{TrustedRootCerts: GceEKRoots},
			wantPass: false,
		},
		{
			name:     "failed with wrong trusted AKs",
			att:      func() *attestpb.Attestation { return att },
			opts:     VerifyOpts{TrustedAKs: []crypto.PublicKey{ak.PublicKey()}},
			wantPass: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, _, err := validateAK(tc.att(), tc.opts)
			if gotPass := (err == nil); gotPass != tc.wantPass {
				t.Errorf("ValidateAK failed, got pass %v, but want %v", gotPass, tc.wantPass)
			}
		})
	}

}

func TestVerifyIgnoreAKPubWithAKCert(t *testing.T) {
	// Make sure that we ignore the AKPub if the AKCert is presented
	rwc := test.GetTPM(t)
	defer client.CheckedClose(t, rwc)

	ak, err := client.AttestationKeyRSA(rwc)
	if err != nil {
		t.Fatalf("failed to generate AK: %v", err)
	}
	defer ak.Close()

	nonce := []byte{0x90, 0x09}
	badAtt, err := ak.Attest(client.AttestOpts{Nonce: nonce})
	if err != nil {
		t.Fatalf("failed to attest: %v", err)
	}
	// Copy "good" certificate into "bad" attestation
	goodAtt := &attestpb.Attestation{}
	if err := proto.Unmarshal(test.COS85Nonce9009, goodAtt); err != nil {
		t.Fatalf("failed to unmarshal attestation: %v", err)
	}
	badAtt.AkCert = goodAtt.GetAkCert()

	opts := VerifyOpts{
		Nonce:             nonce,
		TrustedRootCerts:  GceEKRoots,
		IntermediateCerts: GceEKIntermediates,
	}
	if _, err := VerifyAttestation(badAtt, opts); err == nil {
		t.Error("expected error when calling VerifyAttestation, because the cert is replaced")
	}
}

func TestVerifyFailsWithMalformedIntermediatesInAttestation(t *testing.T) {
	attestBytes := test.COS85Nonce9009
	att := &attestpb.Attestation{}
	if err := proto.Unmarshal(attestBytes, att); err != nil {
		t.Fatalf("failed to unmarshal attestation: %v", err)
	}
	att.IntermediateCerts = [][]byte{[]byte("Not an intermediate cert.")}

	if _, err := VerifyAttestation(att, VerifyOpts{
		Nonce:            []byte{0x90, 0x09},
		TrustedRootCerts: GceEKRoots,
	}); err == nil {
		t.Error("expected error when calling VerifyAttestation with malformed intermediate")
	}
}

func TestGetInstanceInfo(t *testing.T) {
	expectedInstanceInfo := &attestpb.GCEInstanceInfo{
		Zone:          "expected zone",
		ProjectId:     "expected project id",
		ProjectNumber: 0,
		InstanceName:  "expected instance name",
		InstanceId:    1,
	}

	extStruct := gceInstanceInfo{
		Zone:          expectedInstanceInfo.Zone,
		ProjectID:     expectedInstanceInfo.ProjectId,
		ProjectNumber: int64(expectedInstanceInfo.ProjectNumber),
		InstanceName:  expectedInstanceInfo.InstanceName,
		InstanceID:    int64(expectedInstanceInfo.InstanceId),
		SecurityProperties: gceSecurityProperties{
			SecurityVersion: 0,
			IsProduction:    true,
		},
	}

	marshaledExt, err := asn1.Marshal(extStruct)
	if err != nil {
		t.Fatalf("Error marshaling test extension: %v", err)
	}

	ext := []pkix.Extension{{
		Id:    cloudComputeInstanceIdentifierOID,
		Value: marshaledExt,
	}}

	instanceInfo, err := getInstanceInfoFromExtensions(ext)
	if err != nil {
		t.Fatalf("getInstanceInfo returned with error: %v", err)
	}
	if instanceInfo == nil {
		t.Fatal("getInstanceInfo returned nil instance info.")
	}

	if !proto.Equal(instanceInfo, expectedInstanceInfo) {
		t.Errorf("getInstanceInfo did not return expected instance info: got %v, want %v", instanceInfo, expectedInstanceInfo)
	}
}

func TestGetInstanceInfoReturnsNil(t *testing.T) {
	extStruct := gceInstanceInfo{
		Zone:               "zone",
		ProjectID:          "project id",
		ProjectNumber:      0,
		InstanceName:       "instance name",
		InstanceID:         1,
		SecurityProperties: gceSecurityProperties{IsProduction: false},
	}

	marshaledExt, err := asn1.Marshal(extStruct)
	if err != nil {
		t.Fatalf("Error marshaling test extension: %v", err)
	}

	testcases := []struct {
		name string
		ext  []pkix.Extension
	}{
		{
			name: "No extension with expected OID",
			ext: []pkix.Extension{{
				Id:    asn1.ObjectIdentifier([]int{1, 2, 3, 4}),
				Value: []byte("fake extension"),
			}},
		},
		{
			name: "IsProduction is false",
			ext: []pkix.Extension{{
				Id:    cloudComputeInstanceIdentifierOID,
				Value: marshaledExt,
			}},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			instanceInfo, err := getInstanceInfoFromExtensions(tc.ext)
			if err != nil {
				t.Fatalf("getInstanceInfo returned with error: %v", err)
			}

			if instanceInfo != nil {
				t.Error("getInstanceInfo returned instance information, expected nil")
			}
		})
	}
}

func TestGetInstanceInfoError(t *testing.T) {
	testcases := []struct {
		name         string
		instanceInfo *gceInstanceInfo
	}{
		{
			name:         "Extension value is not valid ASN1",
			instanceInfo: nil,
		},
		{
			name: "Negative ProjectNumber",
			instanceInfo: &gceInstanceInfo{
				Zone:               "zone",
				ProjectID:          "project id",
				ProjectNumber:      -1,
				InstanceName:       "instance name",
				InstanceID:         1,
				SecurityProperties: gceSecurityProperties{IsProduction: false},
			},
		},
		{
			name: "Negative InstanceID",
			instanceInfo: &gceInstanceInfo{
				Zone:               "zone",
				ProjectID:          "project id",
				ProjectNumber:      0,
				InstanceName:       "instance name",
				InstanceID:         -1,
				SecurityProperties: gceSecurityProperties{IsProduction: false},
			},
		},
		{
			name: "Negative SecurityVersion",
			instanceInfo: &gceInstanceInfo{
				Zone:          "zone",
				ProjectID:     "project id",
				ProjectNumber: 0,
				InstanceName:  "instance name",
				InstanceID:    1,
				SecurityProperties: gceSecurityProperties{
					SecurityVersion: -1,
					IsProduction:    false,
				},
			},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			var extensionVal []byte
			var err error
			if tc.instanceInfo != nil {
				extensionVal, err = asn1.Marshal(*tc.instanceInfo)
				if err != nil {
					t.Fatalf("Error marshaling test extension: %v", err)
				}
			} else {
				extensionVal = []byte("Not a valid ASN1 extension.")
			}

			_, err = getInstanceInfoFromExtensions([]pkix.Extension{{
				Id:    cloudComputeInstanceIdentifierOID,
				Value: extensionVal,
			}})

			if err == nil {
				t.Error("getInstanceInfo returned successfully, expected error")
			}
		})
	}

	ext := []pkix.Extension{{
		Id:    cloudComputeInstanceIdentifierOID,
		Value: []byte("not valid ASN1"),
	}}

	_, err := getInstanceInfoFromExtensions(ext)
	if err == nil {
		t.Error("getInstanceInfo returned successfully, expected error")
	}
}

func TestGetInstanceInfoASN(t *testing.T) {
	expectedInstanceInfo := &attestpb.GCEInstanceInfo{
		Zone:          "us-west1-b",
		ProjectId:     "jiankun-vm-test",
		ProjectNumber: 620438545889,
		InstanceName:  "jkltest42102",
		InstanceId:    3560342035431930290,
	}

	// The payload is extract from a real AK cert, the ASN1 encoding requires gceSecurityProperties
	// to have explicit ASN tag.
	extPayload := []byte{48, 95, 12, 10, 117, 115, 45, 119, 101, 115, 116, 49, 45, 98, 2, 6, 0, 144, 117, 4, 229, 225, 12, 15, 106, 105, 97, 110, 107, 117, 110, 45, 118, 109, 45, 116, 101, 115, 116, 2, 8, 49, 104, 224, 55, 188, 207, 185, 178, 12, 12, 106, 107, 108, 116, 101, 115, 116, 52, 50, 49, 48, 50, 160, 32, 48, 30, 160, 3, 2, 1, 0, 161, 3, 1, 1, 255, 162, 3, 1, 1, 0, 163, 3, 1, 1, 0, 164, 3, 1, 1, 0, 165, 3, 1, 1, 0}

	ext := []pkix.Extension{{
		Id:    cloudComputeInstanceIdentifierOID,
		Value: extPayload,
	}}

	instanceInfo, err := getInstanceInfoFromExtensions(ext)
	if err != nil {
		t.Fatalf("getInstanceInfo returned with error: %v", err)
	}
	if instanceInfo == nil {
		t.Fatal("getInstanceInfo returned nil instance info.")
	}

	if !proto.Equal(instanceInfo, expectedInstanceInfo) {
		t.Errorf("getInstanceInfo did not return expected instance info: got %v, want %v", instanceInfo, expectedInstanceInfo)
	}
}

func TestValidateAKGCEAndGetGCEInstanceInfo(t *testing.T) {
	testCases := []struct {
		name            string
		certPEM         []byte
		rootCertDER     []byte
		intermediateDER []byte
	}{
		{
			name:            "GCE UCA AK ECC",
			certPEM:         test.GCESignECCCertUCA,
			rootCertDER:     gceEKRootCA,
			intermediateDER: gceEKIntermediateCA3,
		},
		{
			name:            "GCE UCA AK RSA",
			certPEM:         test.GCESignRSACertUCA,
			rootCertDER:     gceEKRootCA,
			intermediateDER: gceEKIntermediateCA3,
		},
		{
			name:            "GCE UCA EK ECC",
			certPEM:         test.GCEEncryptECCCertUCA,
			rootCertDER:     gceEKRootCA,
			intermediateDER: gceEKIntermediateCA3,
		},
		{
			name:            "GCE UCA EK RSA",
			certPEM:         test.GCEEncryptRSACertUCA,
			rootCertDER:     gceEKRootCA,
			intermediateDER: gceEKIntermediateCA3,
		},
		{
			name:            "GCE CAS AK ECC",
			certPEM:         test.GCESignECCCertPCA,
			rootCertDER:     gcpCASEKRootCA,
			intermediateDER: gcpCASEKIntermediateCA3,
		},
		{
			name:            "GCE CAS AK RSA",
			certPEM:         test.GCESignRSACertPCA,
			rootCertDER:     gcpCASEKRootCA,
			intermediateDER: gcpCASEKIntermediateCA3,
		},
		{
			name:            "GCE CAS EK ECC",
			certPEM:         test.GCEEncryptECCCertPCA,
			rootCertDER:     gcpCASEKRootCA,
			intermediateDER: gcpCASEKIntermediateCA3,
		},
		{
			name:            "GCE CAS EK RSA",
			certPEM:         test.GCEEncryptRSACertPCA,
			rootCertDER:     gcpCASEKRootCA,
			intermediateDER: gcpCASEKIntermediateCA3,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			crtBlock, _ := pem.Decode(tc.certPEM)
			if crtBlock.Bytes == nil {
				t.Fatalf("failed to pem.Decode(tc.certPEM)")
			}

			akCrt, err := x509.ParseCertificate(crtBlock.Bytes)
			if err != nil {
				t.Fatalf("x509.ParseCertificate(crtBlock.Bytes): %v", err)
			}
			root, err := x509.ParseCertificate(tc.rootCertDER)
			if err != nil {
				t.Fatalf("x509.ParseCertificate(tc.rootCertDER): %v", err)
			}
			intermediate, err := x509.ParseCertificate(tc.intermediateDER)
			if err != nil {
				t.Fatalf("x509.ParseCertificate(tc.intermediateDER): %v", err)
			}

			if err := VerifyAKCert(akCrt, []*x509.Certificate{root}, []*x509.Certificate{intermediate}); err != nil {
				t.Errorf("ValidateAKCert(%v): %v)", tc.name, err)
			}

			if gceInfo, err := GetGCEInstanceInfo(akCrt); err != nil {
				t.Errorf("GetGCEInstanceInfo(akCrt): %v", err)
			} else {
				t.Log(gceInfo)
				fmt.Print(gceInfo)
			}
		})
	}
}
