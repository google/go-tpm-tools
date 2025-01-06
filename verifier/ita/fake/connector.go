package fake

import (
	"crypto/x509"
	"errors"

	jwt "github.com/golang-jwt/jwt/v4"
	itaconnector "github.com/intel/trustauthority-client/go-connector/connector"
)

// Implements the ITA Connector interface.

type fakeConnector struct {
}

// Confirm that Connector implements ITA's connector interface.
var _ itaconnector.Connector = (*fakeConnector)(nil)

func (c *fakeConnector) GetTokenSigningCertificates() ([]byte, error) {
	return nil, errors.New("unimplemented")
}
func (c *fakeConnector) GetNonce(itaconnector.GetNonceArgs) (itaconnector.GetNonceResponse, error) {
	return itaconnector.GetNonceResponse{}, errors.New("unimplemented")
}
func (c *fakeConnector) GetToken(itaconnector.GetTokenArgs) (itaconnector.GetTokenResponse, error) {
	return itaconnector.GetTokenResponse{}, errors.New("unimplemented")
}
func (c *fakeConnector) Attest(itaconnector.AttestArgs) (itaconnector.AttestResponse, error) {
	return itaconnector.AttestResponse{}, errors.New("unimplemented")
}
func (c *fakeConnector) VerifyToken(string) (*jwt.Token, error) {
	return nil, errors.New("unimplemented")
}

func (c *fakeConnector) AttestEvidence(evidence interface{}, cloudProvider string, reqId string) (itaconnector.AttestResponse, error) {
	return itaconnector.AttestResponse{}, errors.New("unimplemented")
}

func (c *fakeConnector) GetAKCertificate(ekCert *x509.Certificate, akTpmtPublic []byte) ([]byte, []byte, []byte, error) {
	return nil, nil, nil, errors.New("unimplemented")
}
