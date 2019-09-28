package server

import (
	"crypto/elliptic"
	"fmt"
	"math/big"

	"github.com/google/go-tpm-tools/tpm2tools"
	"github.com/google/go-tpm/tpm2"
)

// ECC coordinates need to maintain a specific size based on the curve, so we pad the front with zeros.
func eccIntToBytes(key *big.Int, curve elliptic.Curve) []byte {
	bytes := key.Bytes()
	return append(make([]byte, (curve.Params().BitSize+7)/8-len(bytes)), bytes...)
}

func curveIDToGoCurve(curve tpm2.EllipticCurve) (elliptic.Curve, error) {
	switch curve {
	case tpm2.CurveNISTP224:
		return elliptic.P224(), nil
	case tpm2.CurveNISTP256:
		return elliptic.P256(), nil
	case tpm2.CurveNISTP384:
		return elliptic.P384(), nil
	case tpm2.CurveNISTP521:
		return elliptic.P521(), nil
	default:
		return nil, fmt.Errorf("unsupported curve: %v", curve)
	}
}

func goCurveToCurveID(curve elliptic.Curve) (tpm2.EllipticCurve, error) {
	switch curve.Params().Name {
	case "P-224":
		return tpm2.CurveNISTP224, nil
	case "P-256":
		return tpm2.CurveNISTP256, nil
	case "P-384":
		return tpm2.CurveNISTP384, nil
	case "P-521":
		return tpm2.CurveNISTP521, nil
	default:
		return 0, fmt.Errorf("unsupported curve: %v", curve.Params().Name)
	}
}

func getECCTemplate(curve tpm2.EllipticCurve) tpm2.Public {
	public := tpm2tools.DefaultEKTemplateECC()
	public.ECCParameters.CurveID = curve
	public.ECCParameters.Point.XRaw = nil
	public.ECCParameters.Point.YRaw = nil
	return public
}
