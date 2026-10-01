package activate

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"math/big"
	insecureRand "math/rand"
	"testing"

	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm-tools/tools"
	"github.com/google/go-tpm/tpm2"
)

func mustDecodeBase64(in string, t *testing.T) []byte {
	d, err := base64.StdEncoding.DecodeString(in)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// Test against values independently tested/derived-from from TCG 2.0.38-compliant hardware.
func TestGenerate(t *testing.T) {
	n, ok := new(big.Int).SetString("21781359931719875035142348126986833104406251147281912291128410183893060751686286557235105177011038982931176491091366273712008774268043339103634631078508025847736699362996617038459342869130285665581223736549299195932345592253444537445668838861984376176364138265105552997914795970576284975601851753797509031880704132484924873723738272046545068767315124876824011679223652746414206246649323781826144832659865886735865286033208505363212876011411861316385696414905053502571926429826843117374014575605550176234010475825493066764152314323863950174296024693364113127191375694561947145403061250952175062770094723660429657392597", 10)
	if !ok {
		t.Fatalf("Failed to parse publicN string.")
	}
	public := rsa.PublicKey{
		N: n,
		E: 65537,
	}

	aikDigest := mustDecodeBase64("5snpf9qRfKD2Tb72eLAZqC/a/MyUhg+IvdwDZkTJK9w=", t)
	expected := mustDecodeBase64("AEQAIIQNQu1RkQagbyN+7JlCKUfwBJxIsONZ2/4BD7Q4A15+BcDylTlcvTDgl1CdTuiZk3JcechnrpbfdDXynZ9Sp0uOAwEApDH7zhzLAqsNMSiEdv0xoGrGf/sOCYzSccZ1pDIv7uHON3yMMrX8beOLtCZ9vEQ3vW4i6NdWUJEd/UeMYuc1+Ucu4IB5teUtExhNyvtOXEM7FNXnKooS2ltLA0L7jlkyqwGM7CE0MK4jeFvy13RFNek6S5Rd5MH3RpBuqpL5NjX/yr4g7xCyE2RmXrCSD2DiTm6wU/PtOxYXUVdXeuLaLD69g5pnEAWhARuYa9SomBI8Ewvcxm+slfJpTK/Unrg+FN/d/n0k0IajklNli/jRhuQh5nhrTZXg80kPsEGraSP8eJof49vR643EtoO88jzpTC+/9Tu3yiGCCxEMqR2szA==", t)
	secret := mustDecodeBase64("AQIDBAUGBwgBAgMEBQYHCAECAwQFBgcIAQIDBAUGBwg=", t)

	aikName := &tpm2.HashValue{
		Alg:   tpm2.AlgSHA256,
		Value: aikDigest,
	}

	rng := insecureRand.New(insecureRand.NewSource(99))
	idObject, wrappedCredential, err := generateRSA(aikName, &public, secret, rng)
	if err != nil {
		t.Fatal(err)
	}
	activationBlob := append(idObject, wrappedCredential...)

	if !bytes.Equal(expected, activationBlob) {
		t.Errorf("generate(%v, %v, %v) returned incorrect result", aikName, public, secret)
		t.Logf("  Got:  %v", activationBlob)
		t.Logf("  Want: %v", expected)
	}
}

func TestActivateCredential(t *testing.T) {
	s, err := simulator.Get()
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	// Step 1: Client Side
	// Step 1a: Get the EK
	ek, err := tools.EndorsementKeyRSA(s)
	if err != nil {
		t.Fatalf("Creating EK: %v", err)
	}
	defer ek.Close()

	// Step 1b: Get the AIK
	aikTemplate := tools.DefaultAIKTemplateRSA()
	aikTemplate.Attributes |= tpm2.FlagNoDA // TODO(joerichey): why is this needed
	aik, err := tools.NewKey(s, tpm2.HandleEndorsement, aikTemplate)
	if err != nil {
		t.Fatalf("Creating AIK: %v", err)
	}
	defer aik.Close()
	// Step 1c: Send ek.PublicKey() and aik.PublicArea() to Server

	// Step 2: Server Side
	// Step 2a: Verify aik.PublicArea() properties (this is _not_ comprehensive)
	if aik.PublicArea().NameAlg != tpm2.AlgSHA256 || aik.PublicArea().RSAParameters.Sign.Hash != tpm2.AlgSHA256 {
		t.Fatalf("Expected SHA256")
	}
	if aik.PublicArea().RSAParameters.KeyBits != 2048 {
		t.Fatalf("Expected 2048-bit RSA key")
	}
	if aik.PublicArea().Attributes|tpm2.FlagFixedTPM == 0 {
		t.Fatalf("AIK is not fixed to this TPM")
	}

	// Step 2b: Check ek.PublicKey() against a provided EK Certificate (skipped here)
	// Step 2c: Generate Secret (aka certificateSymProtector)
	secret := make([]byte, 32)
	rand.Reader.Read(secret)

	// Step 2d: Compute/Check aik.Name() against aik.PublicArea() (skipped here)
	// Step 2e: Create credential blob
	idObject, encSecret, err := ServerGenerate(aik.Name(), ek.PublicKey(), secret)
	if err != nil {
		t.Fatalf("Creating encrypted secret: %v", err)
	}
	// Step 2f: Send idObject and encSecret to Client

	// Step 3: Client Side
	decryptedSecret, err := ClientActivate(s, aik.Handle(), ek.Handle(), idObject, encSecret)
	if err != nil {
		t.Fatal(err)
	}

	// Step 4: Server Side - Verify Secure Secret
	if !bytes.Equal(secret, decryptedSecret) {
		t.Fatalf("Secrets did not match, expected %v, got %v", secret, decryptedSecret)
	}

	// Step 5: Issue AIK Certificate (skipped here)
}
