package test

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

var (
	// RootCAKey is a pregenerated 2048-bit RSA key for test root CAs.
	RootCAKey = parsePKCS1PrivateKey(rootCAKeyPEM)
	// IntermediateCAKey is a pregenerated 2048-bit RSA key for test intermediate CAs.
	IntermediateCAKey = parsePKCS1PrivateKey(intermediateCAKeyPEM)
	// LeafKey is a pregenerated 2048-bit RSA key for test leaf certificates.
	LeafKey = parsePKCS1PrivateKey(leafKeyPEM)
)

func parsePKCS1PrivateKey(pemStr string) *rsa.PrivateKey {
	block, _ := pem.Decode([]byte(pemStr))
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		panic(err)
	}
	return key
}

// GetTestCert returns an x509 Certificate for the provided key, signed with the provided parent certificate and key.
// If parentCert and parentKey are nil, the certificate will be self-signed by key.
func GetTestCert(t *testing.T, key *rsa.PrivateKey, issuingURL []string, parentCert *x509.Certificate, parentKey *rsa.PrivateKey) *x509.Certificate {
	t.Helper()

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
		IssuingCertificateURL: issuingURL,
	}

	if parentCert == nil && parentKey == nil {
		parentCert = template
		parentKey = key
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, template, parentCert, key.Public(), parentKey)
	if err != nil {
		t.Fatalf("Unable to create test certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		t.Fatalf("Unable to parse test certificate: %v", err)
	}

	return cert
}

// GetTestCertForKey returns an x509 Certificate for the provided public key.
// The certificate is self-signed by RootCAKey.
func GetTestCertForKey(tb testing.TB, pubKey crypto.PublicKey) *x509.Certificate {
	tb.Helper()

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, pubKey, RootCAKey)
	if err != nil {
		tb.Fatalf("failed to create certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		tb.Fatalf("failed to parse certificate: %v", err)
	}
	return cert
}

// The static test keys below were generated using:
//
//	key, _ := rsa.GenerateKey(rand.Reader, 2048)
//	pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
//
// Equivalently: `openssl genrsa 2048`.
const rootCAKeyPEM = `-----BEGIN RSA PRIVATE KEY-----
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

const intermediateCAKeyPEM = `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAqBaByZQqlBPDEyWbOMAUNS961mijXXDvQqwI46H0sXb2rIxq
C6qV+KvGzudhiGeA+URhmxKx2frz/1fV82fRPCD1pjqtbV3m0djx4MTH7VqumQAT
h3gsjQEDTCtx+HFWhL1JpKYK+YlSj62wC3ANHIme3UGIdSlOU21wPq189yHnqfTj
O4/7S0nDpfDbM5M77H6WK9Taqlzd45RTxhGj+cBpdhI30QNPRu7+F2kFByJGzKBJ
BYm2KBI5TMSGTUCiE3PIKKL6AqSVToQGg3Lu4D1cyMvL7xaqRGj/PsP7xALXSBV3
CEeMcfIOCwRyt1xk0Udo8u+yZ9GiPrqrUbL7zwIDAQABAoIBAEnHm09+bFQT+o/o
dWIrGZOg1CPRyUdmH3dd6Qb122CcLbleZtvZFDwTNlAySuLjP77qL4ewZIWgPEKL
7PsKylJAy2KcJey4B2178uuspG8AW1wIJwpTCwcXdzmTZlLdeNMJ/Q263l1a0/UC
EaBrni21EJjgv4NhzqIbCuZQI2ab8oXukn54Ee9MYjlaooEkepumvexLhj+CIY7n
BU2HYMaBkyGt7TX0QZGOVKw6aAstRz/qQiNlUdXrec5vQMKmtGnUzqDALUHB52Wj
vKloNBOytA5jD7QXyku+cz1M8MNnjrcLq8UnzcV1/hIXadiXW5HGz2/+H+bT831H
SQYklz0CgYEA12vIFFS4aAFeJxpxvu2XecQLoRaK4zOtAYLCb3yjzw0helo7mzyf
lG3qj7tBF9vWM9kwF33Z5HHGyKZs9DWbj4xTA03DA9BwKGQkeEosOnufRm6BxaKg
t9eJpEt8VP+dIFprWzug4UUeuOGbibIMhI/TvpaGbk9flo9y25+dYB0CgYEAx8Aw
COuCWSIlld0pYqRDGxmtemS5WWLY4HnbcXkMGPpSkqb7XK4BnrgJoXMzKMjOcI0p
5dzkmBU6oJqoJsytjF8Y5eAGWTfypBFz/W+u0kuc1IvkeX0zsXAy1/k38ZbDfBuh
TMu1AquKGbyARFBF4FNfGzfse1aDucGY3y5TX9sCgYAydKY6TNWcVqWs1v7JT3Dp
LkfjBRqmuJXPAsdzwWfEuTicJcJMS9i8tTn5TEykv/Ld1gLznaCJZzS+Dmz6jgvP
hXh0D6SbohiC/WGlYwoU8JuPrZZrqfmm1a8BckS+y9gLmeIHTmISIVRezUjW6YMR
EXbw7uSxtZmX9CVc13fO6QKBgQCbjyJZb/9dJuiaY1f9h+ryyfZ94L8vy3kWqA+r
uRcgxKFVsFEFBkYgszZc03g+BNQwdt7wMiyb+7xios7dGHz3Wn/rVaHcDWQbPbRU
5IsDHvuN0zwlGMoPH0+ZPm7A6CZpGqNtSR84axrrnA9QJCum3YatjcnO67s+CHTj
KhKoDQKBgD94heHAp1HbladF+aM+x8vjVqEG0UntfVCvVT8+NUYx7h+3zHzCiAXG
41AIkWlP0bf3qzpo0AMtD3podR9R+bMy5Kd5+oA3pmwM9P/Gqw86awLy5sUhjzPy
xoOicWXMemZppEbPvv5RxiQ2VTD9s6ivWGO4lMFax3JWAnvzVOEM
-----END RSA PRIVATE KEY-----
`

const leafKeyPEM = `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAmTFRlJRRUDi60wg4B019D4G3kZSYsqoKxLNzogqlIpTB9OYb
sYU6DflE563LKNAm3xVq0mAJyJmI5D079S7sM6SzoCDFuch2tS6xx2bXZnt9CkDI
5HDAy8oZc/mPac4P3hVloKBduCSHNQ1qgrEydUdOf5AUJ1KtB4Rm6SsCI4r1hdQM
l4CBvHVkHFDoXomLmEQ5zHthDLOdKHnRnCF/fDvKIynzgnPCWiOfiraKSth75vOU
ogVy/p9O3+6vJMHp6N6LGIptUpesFIMeDaZPHyc9vb4kzqYzzPvl+M0H5pplThVD
oOEH3Sii8i+qd4UncJ7RVEXiJvPnCDc4y3zhKwIDAQABAoIBAEZwLOi6geD3FMAw
CUMiWBynMnbX8pZEJYtoUAT0DBYofD5VB+rKLXV7Zjl46e8sNpNgz6tHyXfZUN5R
YZ5NIwJj+svoBcJ08FBC1i+vk99lbIsoWrbfOWb62FVBLLYjr5wYDpCa7DzdXuX/
8zeArojKbseswfeKxlCsin0v713TswFYBZVtviTCFegjonk0wS2c5GYA+6autXhU
onf3rmmN29xjoDfJjuWBjKSO191rl7IburiZecRLtzn/kfwad0mLGYqRS7Oh5/ra
PrikXeHPCxibZQbQTDna4Qx1nviaIh7JX297hvF4eKnJXAcGdaLOrzr92dpc75yl
5jNS/8ECgYEAyvx1TQUJgRPvEIMgPDH+bwYGWb/xDgVYcrwD8aaV80RqYr3Mbc56
nkJU7b5N60hHVeyv8UOTmavNygxKEec3SUzR3i88IQpkzOS82VtGGp7E4PT3FMtP
FsQ+Si7Xi5eWJt3vUVSz49awX5wR1SE5QXBZ04paqY55NACKJGnBMxECgYEAwTOx
o3Cor+5NyufcfrvIPbvvvAm1R6os92zvb+IFfL711krqQG/GLgphgrL6VJaUBv0s
rTQrhV/AuBLGIx0NI4GkfuuO+sT3HloUYOkyHySB2wuzOG6tP3BtDDBBM4kH21cO
ohxfg8bcfY/EG01FLnS4txfHQuyYCujo8qlj2HsCgYEAkCTk+5OnIyVPr+8d1gE+
iALEQbme6XD8VUWUm2bLtxuPXJ0hbZyh0H6UJtvsIzeJiMfyTSbKyuaI1YESnFIQ
HZpSsi/iyCfEWwfX35YEW2UBtCngx8B0YltrTGylHfjAZMtXZe77a8EKMGr48tuL
+B9benAWX6/P/BCiCKeczbECgYAyPhI9EagckFlUofVaU9UgEMaoXNHywBOPiJm/
u8R3i2V9A+BlP2wHPxXamla1Nq9qHd7HcCC9P4hrlh5GtWBcUnOHuhRlrGEjWIOi
LCKnrKPEZgeGbmnJbKA/IjFiiIkthjc8+ynvqABg+skh3HdYPGxo2Nst0T883xLt
QBXCDwKBgHaazdcQec6DM1usyRRSmNfIjkapPRKRE24yduO8nksiCAIeGr4SX/wo
B8z/o97NTafg0G+N61CMQLAHKs7UhozS71+ZsQKm/LzwDQFE2pr6+oIXs5JwSQrD
yMBo+wEuvR/qnGBBZVC0mRKoIeMfUOQg5MUSi9LfDQuma1/0Trfs
-----END RSA PRIVATE KEY-----
`
