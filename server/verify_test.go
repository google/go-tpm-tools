package server

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
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
	"google.golang.org/protobuf/testing/protocmp"
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
		{cel.RestartPolicyType, test.DebugPCR, []byte(attestpb.RestartPolicy_NEVER.String())},
	}
	hashAlgoList := []crypto.Hash{crypto.SHA256, crypto.SHA1, crypto.SHA512}
	for _, testEvent := range testEvents {
		cos := cel.CosTlv{EventType: testEvent.cosNestedEventType, EventContent: testEvent.eventPayload}
		if err := coscel.AppendEvent(rwc, testEvent.pcr, hashAlgoList, cos); err != nil {
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

	want := attestpb.ContainerState{
		ImageReference: string(testEvents[0].eventPayload),
		ImageDigest:    string(testEvents[1].eventPayload),
		RestartPolicy:  attestpb.RestartPolicy_NEVER}
	if diff := cmp.Diff(state.Cos.Container, &want, protocmp.Transform()); diff != "" {
		t.Errorf("unexpected difference:\n%v", diff)
	}
}

func TestVerifyFailWithTamperedCELContent(t *testing.T) {
	rwc := test.GetTPM(t)
	defer client.CheckedClose(t, rwc)

	ak, err := client.AttestationKeyRSA(rwc)
	if err != nil {
		t.Fatalf("failed to generate AK: %v", err)
	}
	defer ak.Close()

	c := &cel.CEL{}
	measuredHashes := []crypto.Hash{crypto.SHA256, crypto.SHA1, crypto.SHA512}

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
