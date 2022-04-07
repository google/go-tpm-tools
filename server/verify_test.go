package server

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-tpm-tools/cel"
	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm-tools/internal"
	"github.com/google/go-tpm-tools/internal/test"
	attestpb "github.com/google/go-tpm-tools/proto/attest"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
)

var measuredHashes = []crypto.Hash{crypto.SHA1, crypto.SHA256}

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

func TestVerifyBasicAttestation(t *testing.T) {
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

	if _, err := VerifyAttestation(attestation, VerifyOpts{
		Nonce:      nonce,
		TrustedAKs: []crypto.PublicKey{ak.PublicKey()},
	}); err != nil {
		t.Errorf("failed to verify: %v", err)
	}

	if _, err := VerifyAttestation(attestation, VerifyOpts{
		Nonce:      append(nonce, 0),
		TrustedAKs: []crypto.PublicKey{ak.PublicKey()},
	}); err == nil {
		t.Error("using the wrong nonce should make verification fail")
	}

	if _, err := VerifyAttestation(attestation, VerifyOpts{
		Nonce: nonce,
	}); err == nil {
		t.Error("using no trusted AKs should make verification fail")
	}

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyAttestation(attestation, VerifyOpts{
		Nonce:      nonce,
		TrustedAKs: []crypto.PublicKey{priv.Public()},
	}); err == nil {
		t.Error("using a random trusted AKs should make verification fail")
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

func TestVerifyAttestationWithCEL(t *testing.T) {
	rwc := test.GetTPM(t)
	defer client.CheckedClose(t, rwc)

	err := tpm2.PCRReset(rwc, 16)
	if err != nil {
		t.Fatal(err)
	}

	ak, err := client.AttestationKeyRSA(rwc)
	if err != nil {
		t.Fatalf("failed to generate AK: %v", err)
	}
	defer ak.Close()

	coscel := &cel.CEL{}
	testEvents := []struct {
		cosNestedEventType cel.CosType
		pcr                int
		eventPayload       []byte
	}{
		{cel.ImageRefType, test.DebugPCR, []byte("docker.io/bazel/experimental/test:latest")},
		{cel.ImageDigestType, test.DebugPCR, []byte("sha256:781d8dfdd92118436bd914442c8339e653b83f6bf3c1a7a98efcfb7c4fed7483")},
		{cel.RestartPolicyType, test.DebugPCR, []byte(attestpb.RestartPolicy_Never.String())},
		{cel.ImageIDType, test.DebugPCR, []byte("sha256:5DF4A1AC347DCF8CF5E9D0ABC04B04DB847D1B88D3B1CC1006F0ACB68E5A1F4B")},
		{cel.EnvVarType, test.DebugPCR, []byte("foo=bar")},
		{cel.EnvVarType, test.DebugPCR, []byte("bar=baz")},
		{cel.EnvVarType, test.DebugPCR, []byte("baz=foo=bar")},
		{cel.EnvVarType, test.DebugPCR, []byte("empty=")},
		{cel.ArgType, test.DebugPCR, []byte("--x")},
		{cel.ArgType, test.DebugPCR, []byte("--y")},
	}
	for _, testEvent := range testEvents {
		cos := cel.CosTlv{EventType: testEvent.cosNestedEventType, EventContent: testEvent.eventPayload}
		if err := coscel.AppendEvent(rwc, testEvent.pcr, measuredHashes, cos); err != nil {
			t.Fatal(err)
		}
	}

	var buf bytes.Buffer
	if err := coscel.EncodeCEL(&buf); err != nil {
		t.Fatal(err)
	}

	nonce := []byte("super secret nonce")
	attestation, err := ak.Attest(client.AttestOpts{Nonce: nonce, CanonicalEventLog: buf.Bytes()})
	if err != nil {
		t.Fatalf("failed to attest: %v", err)
	}

	opts := VerifyOpts{
		Nonce:      nonce,
		TrustedAKs: []crypto.PublicKey{ak.PublicKey()},
	}
	state, err := VerifyAttestation(attestation, opts)
	if err != nil {
		t.Fatalf("failed to verify: %v", err)
	}

	expectedEnvVars := make(map[string]string)
	expectedEnvVars["foo"] = "bar"
	expectedEnvVars["bar"] = "baz"
	expectedEnvVars["baz"] = "foo=bar"
	expectedEnvVars["empty"] = ""

	want := attestpb.ContainerState{
		ImageReference: string(testEvents[0].eventPayload),
		ImageDigest:    string(testEvents[1].eventPayload),
		RestartPolicy:  attestpb.RestartPolicy_Never,
		ImageId:        string(testEvents[3].eventPayload),
		EnvVars:        expectedEnvVars,
		Args:           []string{string(testEvents[8].eventPayload), string(testEvents[9].eventPayload)},
	}
	if diff := cmp.Diff(state.Cos.Container, &want, protocmp.Transform()); diff != "" {
		t.Errorf("unexpected difference:\n%v", diff)
	}
}

func TestVerifyFailWithTamperedCELContent(t *testing.T) {
	rwc := test.GetTPM(t)
	defer client.CheckedClose(t, rwc)

	err := tpm2.PCRReset(rwc, tpmutil.Handle(test.DebugPCR))
	if err != nil {
		t.Fatal(err)
	}

	ak, err := client.AttestationKeyRSA(rwc)
	if err != nil {
		t.Fatalf("failed to generate AK: %v", err)
	}
	defer ak.Close()

	c := &cel.CEL{}

	cosEvent := cel.CosTlv{EventType: cel.ImageRefType, EventContent: []byte("docker.io/bazel/experimental/test:latest")}
	cosEvent2 := cel.CosTlv{EventType: cel.ImageDigestType, EventContent: []byte("sha256:781d8dfdd92118436bd914442c8339e653b83f6bf3c1a7a98efcfb7c4fed7483")}
	if err := c.AppendEvent(rwc, test.DebugPCR, measuredHashes, cosEvent); err != nil {
		t.Fatalf("failed to append event: %v", err)
	}
	if err := c.AppendEvent(rwc, test.DebugPCR, measuredHashes, cosEvent2); err != nil {
		t.Fatalf("failed to append event: %v", err)
	}

	// modify the first record content, but not the record digest
	modifiedRecord := cel.CosTlv{EventType: cel.ImageDigestType, EventContent: []byte("sha256:000000000000000000000000000000000000000000000000000000000000000")}
	modifiedTLV, err := modifiedRecord.GetTLV()
	if err != nil {
		t.Fatal(err)
	}
	c.Records[0].Content = modifiedTLV

	var buf bytes.Buffer
	if err := c.EncodeCEL(&buf); err != nil {
		t.Fatal(err)
	}

	nonce := []byte("super secret nonce")
	attestation, err := ak.Attest(client.AttestOpts{Nonce: nonce, CanonicalEventLog: buf.Bytes()})
	if err != nil {
		t.Fatalf("failed to attest: %v", err)
	}

	opts := VerifyOpts{
		Nonce:      nonce,
		TrustedAKs: []crypto.PublicKey{ak.PublicKey()},
	}
	if _, err := VerifyAttestation(attestation, opts); err == nil {
		t.Fatalf("VerifyAttestation should fail due to modified content")
	} else if !strings.Contains(err.Error(), "CEL record content digest verification failed") {
		t.Fatalf("expect to get digest verification failed error, but got %v", err)
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

func TestVerifyFailWithCertsAndPubkey(t *testing.T) {
	att := &attestpb.Attestation{}
	if err := proto.Unmarshal(test.COS85NoNonce, att); err != nil {
		t.Fatalf("failed to unmarshal attestation: %v", err)
	}

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
	if _, err := VerifyAttestation(att, opts); err == nil {
		t.Error("Verified attestation even with multiple trust methods")
	}
}

func TestVerifyAttestationEmptyRootsIntermediates(t *testing.T) {
	attestBytes := test.COS85NoNonce
	att := &attestpb.Attestation{}
	if err := proto.Unmarshal(attestBytes, att); err != nil {
		t.Fatalf("failed to unmarshal attestation: %v", err)
	}

	if _, err := VerifyAttestation(att, VerifyOpts{
		TrustedRootCerts:  nil,
		IntermediateCerts: nil,
	}); err == nil {
		t.Error("expected error when calling VerifyAttestation with empty roots and intermediates")
	}

	if _, err := VerifyAttestation(att, VerifyOpts{}); err == nil {
		t.Error("expected error when calling VerifyAttestation with empty VerifyOpts")
	}
}

func TestVerifyAttestationMissingRoots(t *testing.T) {
	attestBytes := test.COS85NoNonce
	att := &attestpb.Attestation{}
	if err := proto.Unmarshal(attestBytes, att); err != nil {
		t.Fatalf("failed to unmarshal attestation: %v", err)
	}

	if _, err := VerifyAttestation(att, VerifyOpts{
		IntermediateCerts: GceEKIntermediates,
	}); err == nil {
		t.Error("expected error when calling VerifyAttestation with missing roots")
	}
}

func TestVerifyAttestationMissingIntermediates(t *testing.T) {
	attestBytes := test.COS85NoNonce
	att := &attestpb.Attestation{}
	if err := proto.Unmarshal(attestBytes, att); err != nil {
		t.Fatalf("failed to unmarshal attestation: %v", err)
	}

	if _, err := VerifyAttestation(att, VerifyOpts{
		TrustedRootCerts: GceEKRoots,
	}); err == nil {
		t.Error("expected error when calling VerifyAttestation with missing intermediates")
	}
}

func TestVerifyMismatchedAKPubAndAKCert(t *testing.T) {
	// Make sure that we fail verification if the AKPub and AKCert don't match
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
		t.Error("expected error when calling VerifyAttestation with mismatched public key and cert")
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

	instanceInfo, err := getInstanceInfo(ext)
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
			instanceInfo, err := getInstanceInfo(tc.ext)
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

			_, err = getInstanceInfo([]pkix.Extension{{
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

	_, err := getInstanceInfo(ext)
	if err == nil {
		t.Error("getInstanceInfo returned successfully, expected error")
	}
}
