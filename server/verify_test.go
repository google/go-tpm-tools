package server

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"fmt"
	"hash"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	sgtest "github.com/google/go-sev-guest/testing"
	"github.com/google/go-sev-guest/verify"
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
	test.SkipForRealTPM(t)
	rwc := test.GetTPM(t)
	defer client.CheckedClose(t, rwc)

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
		{cel.ImageRefType, cel.CosEventPCR, []byte("docker.io/bazel/experimental/test:latest")},
		{cel.ImageDigestType, cel.CosEventPCR, []byte("sha256:781d8dfdd92118436bd914442c8339e653b83f6bf3c1a7a98efcfb7c4fed7483")},
		{cel.RestartPolicyType, cel.CosEventPCR, []byte(attestpb.RestartPolicy_Never.String())},
		{cel.ImageIDType, cel.CosEventPCR, []byte("sha256:5DF4A1AC347DCF8CF5E9D0ABC04B04DB847D1B88D3B1CC1006F0ACB68E5A1F4B")},
		{cel.EnvVarType, cel.CosEventPCR, []byte("foo=bar")},
		{cel.EnvVarType, cel.CosEventPCR, []byte("bar=baz")},
		{cel.EnvVarType, cel.CosEventPCR, []byte("baz=foo=bar")},
		{cel.EnvVarType, cel.CosEventPCR, []byte("empty=")},
		{cel.ArgType, cel.CosEventPCR, []byte("--x")},
		{cel.ArgType, cel.CosEventPCR, []byte("--y")},
		{cel.OverrideArgType, cel.CosEventPCR, []byte("--x")},
		{cel.OverrideEnvType, cel.CosEventPCR, []byte("empty=")},
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

	expectedOverriddenEnvVars := make(map[string]string)
	expectedOverriddenEnvVars["empty"] = ""

	want := attestpb.ContainerState{
		ImageReference:    string(testEvents[0].eventPayload),
		ImageDigest:       string(testEvents[1].eventPayload),
		RestartPolicy:     attestpb.RestartPolicy_Never,
		ImageId:           string(testEvents[3].eventPayload),
		EnvVars:           expectedEnvVars,
		Args:              []string{string(testEvents[8].eventPayload), string(testEvents[9].eventPayload)},
		OverriddenEnvVars: expectedOverriddenEnvVars,
		OverriddenArgs:    []string{string(testEvents[10].eventPayload)},
	}
	if diff := cmp.Diff(state.Cos.Container, &want, protocmp.Transform()); diff != "" {
		t.Errorf("unexpected difference:\n%v", diff)
	}
}

func TestVerifyFailWithTamperedCELContent(t *testing.T) {
	test.SkipForRealTPM(t)
	rwc := test.GetTPM(t)
	defer client.CheckedClose(t, rwc)

	ak, err := client.AttestationKeyRSA(rwc)
	if err != nil {
		t.Fatalf("failed to generate AK: %v", err)
	}
	defer ak.Close()

	c := &cel.CEL{}

	cosEvent := cel.CosTlv{EventType: cel.ImageRefType, EventContent: []byte("docker.io/bazel/experimental/test:latest")}
	cosEvent2 := cel.CosTlv{EventType: cel.ImageDigestType, EventContent: []byte("sha256:781d8dfdd92118436bd914442c8339e653b83f6bf3c1a7a98efcfb7c4fed7483")}
	if err := c.AppendEvent(rwc, cel.CosEventPCR, measuredHashes, cosEvent); err != nil {
		t.Fatalf("failed to append event: %v", err)
	}
	if err := c.AppendEvent(rwc, cel.CosEventPCR, measuredHashes, cosEvent2); err != nil {
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

func TestVerifyAttestationWithSevSnp(t *testing.T) {

	pcr0 := uint32(0)
	algorithms := []struct {
		ID         uint16
		DigestSize uint16
		Make       func() hash.Hash
	}{
		{ID: 0x04, DigestSize: 0x14, Make: crypto.SHA1.New},
		{ID: 0xb, DigestSize: 0x20, Make: crypto.SHA256.New},
		{ID: 0xc, DigestSize: 0x30, Make: crypto.SHA384.New},
	}
	specEventInfo := []byte{
		'S', 'p', 'e', 'c', ' ', 'I', 'D', ' ', 'E', 'v', 'e', 'n', 't', '0', '3', 0,
		0, 0, 0, 0, // platformClass
		0,                              // specVersionMinor,
		2,                              // specVersionMajor,
		0,                              // specErrata
		2,                              // uintnSize
		byte(len(algorithms)), 0, 0, 0} // NumberOfAlgorithms
	for _, alg := range algorithms {
		var algInfo [4]byte
		binary.LittleEndian.PutUint16(algInfo[0:2], alg.ID)
		binary.LittleEndian.PutUint16(algInfo[2:4], alg.DigestSize)
		specEventInfo = append(specEventInfo, algInfo[:]...)
	}
	vendorInfoSize := byte(0)
	specEventInfo = append(specEventInfo, vendorInfoSize)

	specEventHeader := make([]byte, 32)
	evNoAction := uint32(0x03)
	binary.LittleEndian.PutUint32(specEventHeader[0:4], pcr0)
	binary.LittleEndian.PutUint32(specEventHeader[4:8], evNoAction)
	binary.LittleEndian.PutUint32(specEventHeader[28:32], uint32(len(specEventInfo)))
	specEvent := append(specEventHeader, specEventInfo...)

	// After the Spec ID Event, all events must use all the specified digest algorithms.
	extendHashes := func(buffer []byte, info []byte) []byte {
		var numberOfDigests [4]byte
		binary.LittleEndian.PutUint32(numberOfDigests[:], uint32(len(algorithms)))
		buffer = append(buffer, numberOfDigests[:]...)
		for _, alg := range algorithms {
			digest := make([]byte, 2+alg.DigestSize)
			binary.LittleEndian.PutUint16(digest[0:2], alg.ID)
			h := alg.Make()
			h.Write(info)
			copy(digest[2:], h.Sum(nil))
			buffer = append(buffer, digest...)
		}
		return buffer
	}
	writeTpm2Event := func(buffer []byte, pcr uint32, eventType uint32, info []byte) []byte {
		header := make([]byte, 8)
		binary.LittleEndian.PutUint32(header[0:4], pcr)
		binary.LittleEndian.PutUint32(header[4:8], eventType)
		buffer = append(buffer, header...)

		buffer = extendHashes(buffer, info)

		var eventSize [4]byte
		binary.LittleEndian.PutUint32(eventSize[:], uint32(len(info)))
		buffer = append(buffer, eventSize[:]...)

		return append(buffer, info...)
	}
	evSCRTMversion := uint32(0x08)
	versionEventInfo := []byte{
		'G', 0, 'C', 0, 'E', 0, ' ', 0,
		'V', 0, 'i', 0, 'r', 0, 't', 0, 'u', 0, 'a', 0, 'l', 0, ' ', 0,
		'F', 0, 'i', 0, 'r', 0, 'm', 0, 'w', 0, 'a', 0, 'r', 0, 'e', 0, ' ', 0,
		'v', 0, '1', 0, 0, 0}
	withVersionEvent := writeTpm2Event(specEvent, pcr0, evSCRTMversion, versionEventInfo)

	sevSnpEnum := byte(4)
	nonHostEventInfo := []byte{
		'G', 'C', 'E', ' ', 'N', 'o', 'n', 'H', 'o', 's', 't', 'I', 'n', 'f', 'o', 0,
		sevSnpEnum, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	evNonHostInfo := uint32(0x11)
	snpEventLog := writeTpm2Event(withVersionEvent, pcr0, evNonHostInfo, nonHostEventInfo)

	rwc := test.GetSimulatorWithLog(t, snpEventLog)
	defer client.CheckedClose(t, rwc)

	ak, err := client.AttestationKeyRSA(rwc)
	if err != nil {
		t.Fatalf("failed to generate AK: %v", err)
	}
	defer ak.Close()

	nonce := []byte("super secret nonce")
	var nonce64 [64]byte
	copy(nonce64[:], []byte("alternate secret nonce"))
	sevTestDevice, err := sgtest.TcDevice([]sgtest.TestCase{
		{
			Input:  nonce64,
			Output: sgtest.TestRawReport(nonce64),
		},
	}, &sgtest.DeviceOptions{Now: time.Now()})
	if err != nil {
		t.Fatalf("failed to create test device: %v", err)
	}
	attestation, err := ak.Attest(client.AttestOpts{
		Nonce:     nonce,
		TEEDevice: &client.SevSnpDevice{Device: sevTestDevice},
		TEENonce:  nonce64[:],
	})
	if err != nil {
		t.Fatalf("failed to attest: %v", err)
	}

	goodSnpRoot := map[string][]*verify.AMDRootCerts{
		"Milan": {
			{
				Product: "Milan",
				AskX509: sevTestDevice.Signer.Ask,
				ArkX509: sevTestDevice.Signer.Ark,
			},
		},
	}
	tcs := []struct {
		name    string
		opts    VerifyOpts
		wantErr string
	}{
		{
			name: "Happy path",
			opts: VerifyOpts{
				Nonce:      nonce,
				TrustedAKs: []crypto.PublicKey{ak.PublicKey()},
				TEEOpts: &VerifySnpOpts{
					ReportData:         nonce64,
					TrustedRoots:       goodSnpRoot,
					AllowDebugTestOnly: true,
				},
			},
		},
		{
			name: "Wrong TEE nonce",
			opts: VerifyOpts{
				Nonce:      nonce,
				TrustedAKs: []crypto.PublicKey{ak.PublicKey()},
				TEEOpts: &VerifySnpOpts{
					ReportData: func() [64]byte {
						var badNonce [64]byte
						copy(badNonce[:], []byte("soooo baaad"))
						return badNonce
					}(),
					TrustedRoots:       goodSnpRoot,
					AllowDebugTestOnly: true,
				},
			},
			wantErr: "report field REPORT_DATA",
		},
		{
			name: "Bad sev root",
			opts: VerifyOpts{
				Nonce:      nonce,
				TrustedAKs: []crypto.PublicKey{ak.PublicKey()},
				TEEOpts: &VerifySnpOpts{
					ReportData: nonce64,
					TrustedRoots: map[string][]*verify.AMDRootCerts{
						"Milan": {
							{
								Product: "Milan",
								// Backwards, oops
								AskX509: sevTestDevice.Signer.Ark,
								ArkX509: sevTestDevice.Signer.Ask,
							},
						},
					},
					AllowDebugTestOnly: true,
				},
			},
			wantErr: "error verifying VCEK certificate",
		},
		{
			name: "woops all debug",
			opts: VerifyOpts{
				Nonce:      nonce,
				TrustedAKs: []crypto.PublicKey{ak.PublicKey()},
				TEEOpts: &VerifySnpOpts{
					ReportData:   nonce64,
					TrustedRoots: goodSnpRoot,
				},
			},
			wantErr: "found unauthorized debug capability",
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := VerifyAttestation(attestation, tc.opts); (err == nil && tc.wantErr != "") ||
				(err != nil && !strings.Contains(err.Error(), tc.wantErr)) {
				t.Errorf("VerifyAttestation(_, %v) = %v, want %q", tc.opts, err, tc.wantErr)
			}
		})
	}
}
