package fake

import "github.com/golang-jwt/jwt/v4"

// Verify that Claims implements jwt.Claims.
var _ jwt.Claims = Claims{}

// Claims contains information to be formatted into a fake JWT.
type Claims struct {
	jwt.RegisteredClaims
	ContainerImageSignatures []ContainerImageSignatureClaims `json:"container_image_signatures"`
}

// ContainerImageSignatureClaims contains claims about a container image signature.
type ContainerImageSignatureClaims struct {
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
	PubKey    string `json:"public_key"`
	SigAlg    string `json:"signature_algorithm"`
}

// Valid is necessary to implement the jwt.Claims interface.
func (c Claims) Valid() error {
	return nil
}
