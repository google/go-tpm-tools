package client_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"fmt"
	"io"
	"log"

	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm-tools/internal"
	"github.com/google/go-tpm-tools/server"
	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/legacy/tpm2"
)

var tpmHashAlg = tpm2.AlgSHA256
var hashAlg = crypto.SHA256

func ExampleKey_Quote() {
	// On verifier, make the nonce.
	nonce := make([]byte, 8)

	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		log.Fatalf("failed to create nonce: %v", err)
	}

	// On client machine, generate the TPM quote.
	// TODO: use real TPM.
	simulator, err := simulator.Get()
	if err != nil {
		log.Fatalf("failed to initialize simulator: %v", err)
	}
	defer simulator.Close()

	ak, err := client.AttestationKeyECC(simulator)
	if err != nil {
		log.Fatalf("failed to create attestation key: %v", err)
	}
	defer ak.Close()

	pcr7 := tpm2.PCRSelection{
		Hash: tpm2.AlgSHA256,
		PCRs: []int{7},
	}

	quote, err := ak.Quote(pcr7, nonce)
	if err != nil {
		log.Fatalf("failed to create quote: %v", err)
	}

	// On verifier, verify the quote against a stored public key/AK
	// certificate's public part and the nonce passed.
	if err := internal.VerifyQuote(quote, ak.PublicKey(), nonce); err != nil {
		// TODO: handle verify error.
		log.Fatalf("failed to verify quote: %v", err)
	}
	// Output:
}
func ExampleKey_Import_eK() {
	// On client machine, EK should already exist.
	// TODO: use real TPM.
	simulator, err := simulator.Get()
	if err != nil {
		log.Fatalf("failed to initialize simulator: %v", err)
	}
	defer simulator.Close()

	ek, err := client.EndorsementKeyECC(simulator)
	if err != nil {
		log.Fatalf("failed to create endorsement key: %v", err)
	}

	// Pass EK pub to remote server, typically via an EK cert.
	// The server can then associate the EK public to the corresponding client.

	// Data to seal to EK public.
	secret := []byte("secret data")

	// ek.PublicKey already verified using the manufacturer-signed EK cert.
	importBlob, err := server.CreateImportBlob(ek.PublicKey(), secret, nil)
	if err != nil {
		log.Fatalf("failed to create import blob: %v", err)
	}

	// On client, import the EK.
	output, err := ek.Import(importBlob)
	if err != nil {
		// TODO: handle import failure.
		log.Fatalf("failed to import blob: %v", err)
	}

	fmt.Println(string(output))
	// TODO: use output of ek.Import.
	// Output: secret data
}

func ExampleKey_Attest() {
	// On verifier, make the nonce.
	nonce := make([]byte, 8)

	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		log.Fatalf("failed to create nonce: %v", err)
	}

	// On client machine, generate the TPM quote.
	// TODO: use real TPM.
	simulator, err := simulator.Get()
	if err != nil {
		log.Fatalf("failed to initialize simulator: %v", err)
	}
	defer simulator.Close()

	ak, err := client.AttestationKeyECC(simulator)
	if err != nil {
		log.Fatalf("failed to create attestation key: %v", err)
	}
	defer ak.Close()

	attestation, err := ak.Attest(client.AttestOpts{Nonce: nonce})
	if err != nil {
		log.Fatalf("failed to attest: %v", err)
	}

	// TODO: establish trust in the AK (typically via an AK certificate signed
	// by the manufacturer).
	// On verifier, verify the Attestation message. This:
	//  - checks the quote(s) against a stored public key/AK
	// certificate's public part and the expected nonce.
	//  - replays the event log against the quoted PCRs
	//  - extracts events into a MachineState message.
	// TODO: decide which hash algorithm to use in the quotes. SHA1 is
	// typically undesirable but is the only event log option on some distros.
	_, err = server.VerifyAttestation(attestation, server.VerifyOpts{Nonce: nonce, TrustedAKs: []crypto.PublicKey{ak.PublicKey()}})
	if err != nil {
		// TODO: handle parsing or replay error.
		log.Fatalf("failed to read PCRs: %v", err)
	}
	fmt.Println(attestation)
	// TODO: use events output of ParseMachineState.
}

func Example_sealAndUnseal() {
	// TODO: use real TPM.
	simulator, err := simulator.Get()
	if err != nil {
		log.Fatalf("failed to initialize simulator: %v", err)
	}
	defer simulator.Close()

	srk, err := client.StorageRootKeyECC(simulator)
	if err != nil {
		log.Fatalf("failed to create storage root key: %v", err)
	}

	sealedSecret := []byte("secret password")

	sel := tpm2.PCRSelection{Hash: tpm2.AlgSHA256, PCRs: []int{7}}
	// Seal the data to the current value of PCR7.
	sealedBlob, err := srk.Seal([]byte(sealedSecret), client.SealOpts{Current: sel})
	if err != nil {
		log.Fatalf("failed to seal to SRK: %v", err)
	}

	// Validate by unsealing the sealed blob. Because it is possible that a TPM can seal a secret
	// properly but fail to certify it (thus we shouldn't unseal it because the creation status
	// cannot be verify). This ensures we can unseal the sealed blob, and that its contents are
	// equal to what we sealed.
	output, err := srk.Unseal(sealedBlob, client.UnsealOpts{CertifyCurrent: sel})
	if err != nil {
		// TODO: handle unseal error.
		log.Fatalf("failed to unseal blob: %v", err)
	}
	// TODO: use unseal output.
	fmt.Println(string(output))
	// Output: secret password
}

func ExampleKey_GetSigner() {
	// TODO: use real TPM.
	simulator, err := simulator.Get()
	if err != nil {
		log.Fatalf("failed to initialize simulator: %v", err)
	}
	defer simulator.Close()

	exampleECCSignerTemplate := tpm2.Public{
		Type:    tpm2.AlgECC,
		NameAlg: tpm2.AlgSHA256,
		Attributes: tpm2.FlagSign | tpm2.FlagFixedTPM |
			tpm2.FlagFixedParent | tpm2.FlagSensitiveDataOrigin | tpm2.FlagUserWithAuth,
		ECCParameters: &tpm2.ECCParams{
			CurveID: tpm2.CurveNISTP256,
			Sign: &tpm2.SigScheme{
				Alg:  tpm2.AlgECDSA,
				Hash: tpmHashAlg,
			},
		},
	}
	key, err := client.NewKey(simulator, tpm2.HandleOwner, exampleECCSignerTemplate)
	if err != nil {
		log.Fatalf("failed to create signing key: %v", err)
	}
	defer key.Close()

	toSign := []byte("message to sign")
	hash := hashAlg.New()
	hash.Write(toSign)
	digest := hash.Sum(nil)

	cryptoSigner, err := key.GetSigner()
	if err != nil {
		log.Fatalf("failed to create crypto signer: %v", err)
	}
	sig, err := cryptoSigner.Sign(nil, digest, hashAlg)
	if err != nil {
		log.Fatalf("failed to sign: %v", err)
	}

	// Verifier needs to establish trust in signer.Public() (via a certificate,
	// TPM2_ActivateCredential, TPM2_Certify).
	if !ecdsa.VerifyASN1(cryptoSigner.Public().(*ecdsa.PublicKey), digest, sig) {
		// TODO: handle signature verification failure.
		log.Fatal("failed to verify digest")
	}
	// Output:
}

func ExampleKey_SignData() {
	// TODO: use real TPM.
	simulator, err := simulator.Get()
	if err != nil {
		log.Fatalf("failed to initialize simulator: %v", err)
	}
	defer simulator.Close()

	exampleECCSignerTemplate := tpm2.Public{
		Type:    tpm2.AlgECC,
		NameAlg: tpm2.AlgSHA256,
		Attributes: tpm2.FlagSign | tpm2.FlagFixedTPM |
			tpm2.FlagFixedParent | tpm2.FlagSensitiveDataOrigin | tpm2.FlagUserWithAuth,
		ECCParameters: &tpm2.ECCParams{
			CurveID: tpm2.CurveNISTP256,
			Sign: &tpm2.SigScheme{
				Alg:  tpm2.AlgECDSA,
				Hash: tpmHashAlg,
			},
		},
	}
	key, err := client.NewKey(simulator, tpm2.HandleOwner, exampleECCSignerTemplate)
	if err != nil {
		log.Fatalf("failed to create signing key: %v", err)
	}
	defer key.Close()

	toSign := []byte("message to sign")
	hash := hashAlg.New()
	hash.Write(toSign)
	digest := hash.Sum(nil)

	sig, err := key.SignData(toSign)
	if err != nil {
		log.Fatalf("failed to sign data: %v", err)
	}

	// Verifier needs to establish trust in signer.Public() (via a certificate,
	// TPM2_ActivateCredential, TPM2_Certify).
	if !ecdsa.VerifyASN1(key.PublicKey().(*ecdsa.PublicKey), digest, sig) {
		// TODO: handle signature verification failure.
		log.Fatal("failed to verify digest")
	}
	// Output:
}
