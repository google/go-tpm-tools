// Package test provides helper methods for testing. It should never be
// included in non-test libraries/binaries.
package test

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io"
	"testing"

	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

var (
	testExternalKey = parseExternalKey(testExternalKeyPEM)
	externalPublic  = tpm2.Public{
		Type:       tpm2.AlgRSA,
		NameAlg:    tpm2.AlgSHA1,
		Attributes: tpm2.FlagSign | tpm2.FlagUserWithAuth,
		RSAParameters: &tpm2.RSAParams{
			Sign: &tpm2.SigScheme{
				Alg:  tpm2.AlgRSASSA,
				Hash: tpm2.AlgSHA1,
			},
			KeyBits:     2048,
			ExponentRaw: uint32(testExternalKey.E),
			ModulusRaw:  testExternalKey.N.Bytes(),
		},
	}
	externalPrivate = tpm2.Private{
		Type:      tpm2.AlgRSA,
		Sensitive: testExternalKey.Primes[0].Bytes(),
	}
)

func parseExternalKey(pemStr string) *rsa.PrivateKey {
	block, _ := pem.Decode([]byte(pemStr))
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		panic(err)
	}
	return key
}

// LoadExternalKey loads an external key into the TPM simulator and returns
// its handle. If any errors occur, calls Fatal() on the passed testing.TB.
func LoadExternalKey(tb testing.TB, rw io.ReadWriter) tpmutil.Handle {
	tb.Helper()
	handle, _, err := tpm2.LoadExternal(rw, externalPublic, externalPrivate, tpm2.HandleNull)
	if err != nil {
		tb.Fatalf("failed to load external key: %v", err)
	}
	return handle
}

// The static test key below was generated using:
//
//	key, _ := rsa.GenerateKey(rand.Reader, 2048)
//	pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
//
// Equivalently: `openssl genrsa 2048`.
const testExternalKeyPEM = `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAsq1VdY5qOTp7Adc1WADbpf3jsXoGD54Qg7SrQjIuWDJxKXnt
dZ+uuiYdPekGzy5neMf1xIwa9bkz7eiwqgxWM0zWvuKv96iNIqJhV3ccFjp/xu/g
QCAPA2Va02Afe8blB/TgvRnYB0SJ0U4DzyPfaTihw6NYxv51qIRPD9FXAF6h2H+c
w4LNkRWI22iGxJN5aIT/x+yjh2YyLoWyuRyRNiqLEt2SX9Wx45TFxAcK50P+LP0W
Rmvum+jVQS9Jzs+IwGcR4P6QYu2h6u+cuPHphkSQdLyD3CPV4DPs+YjDywMXxGB4
CaG01gDYyea2KMHn25FRxQpHHKid2POWeA3QmwIDAQABAoIBAByuDOsfLna8J9Vu
TV4wWRFmVN9+di2Ykg8J93lbI6w9gIOHUjHQrVOs3YG7/z9PNAWjlxPy5zrs/ORh
tsW80DNQ0KF4MoWetPTLurM257e7sRnmFAlG/BHv+Wm3YqZUERw7Vr2TweS8wCBs
FNlxaSFzGSgVdqEOZCVmA2jHEd95jF6I/a1V5wGS4oo0Oi5FqEuvZ0Nh3rJvJ4s9
InwMo/1TXXihcICHy65LBQTnWz2T/DG5KYuNSjRIhJwY/w71OHXlUcPbV77NesuL
CCni0cgrk2qP3wuGX1jZG+7jKSZwqc/f5BIiR/p3lAFbQZDfZ0SxvodgFopwZ0Av
9+nk8KkCgYEAymm6h5q4OPdR5rqvdFMlCbXNG5Ye5JFZIXKNoE1uvWzDPjg0S+m4
gl8gZXnrPHe7TzBXOjXHAcghEv8udLodiJrE/+wbNxiYVWZbd2YVAQCvPr6J/P/I
8uuxI9VeNbr4z8udDZMHVXlZ0WLeamR6R+GP7So1LY87BjVBrWE3WtMCgYEA4frv
X39EOgLo0+eKIZR3dpbGqhkfvkvynOkrGT4IxOHEY7F/3V4+3HURy+qOqutTDZZL
kUOL5tbBiyvIOTxbFl/4pAP5P5zTcN/87jekz26Qq0B0N/RgXX4R34Shgdf5oRzZ
LGHWB2Tv+dx4bMNLgMaYiXVaPiccGXTRp29HBhkCgYBtNqj3e+rEieV+CeKbcDU+
zQIzTUez6hzeaDG0ebMzr9iU3LyS7TOp3GvddPAQ+0Vsj9ewx81tz67Q0jEduEIx
L9j1gU6Z5sJi6cyWWtUgal8kCqjngpfJQpSckga4FP8lF2bRKTC+1LA6ww7g9v/n
gvQmciypPWwKiHe8dgTpEwKBgQDFSc6yEOn/u4qJdhuiNXwWjIvk9QpBmQy28Nov
r3j4aiKK5uw6140J6yseXCkyD0DzG8PdjpsVbWiLmC21ynu7jQ4GI3H3l3MBmIu5
bdr1PhIPcLYGI9P9y5LPEXvvYB8QCZ+Qn9m7muPnwBNi4R2Jz9hcKZgfqwVdNB/V
jdD0AQKBgQCHi/vaPqxZkK15uKzCmsrKKrXOKgQyEDkr+5pLJHI1IoPTeEhVfzIX
ygIAam0tgXFsiQghxYZ4H9bIU8eYjBICZkVzErr7O6LOavGZ9wCmlH7I2LsB9MFZ
pcMmajsKtFip3//cjBdQO+Cgy3lYQu6GMmUbTnbZmOaa+THGNAhCkQ==
-----END RSA PRIVATE KEY-----
`
