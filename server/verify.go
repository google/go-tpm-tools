package server

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/subtle"
	"fmt"

	"github.com/google/go-tpm-tools/client"
	tpmpb "github.com/google/go-tpm-tools/proto"
	"github.com/google/go-tpm/tpm2"
)

// Verify checks an AK's signature on a Quote against the quoted data and extra data.
// Then, it matches that quoted data (PCR digest) against a group of PCRs.
//
// Verify supports ECDSA and RSASSA signature verification.
func Verify(pubKey crypto.PublicKey, quote *tpmpb.Quote, pcrs *tpmpb.Pcrs, extraData []byte) error {
	sig, err := tpm2.DecodeSignature(bytes.NewBuffer(quote.GetRawSig()))
	if err != nil {
		return fmt.Errorf("signature decoding failed: %v", err)
	}

	var hash crypto.Hash
	switch pub := pubKey.(type) {
	case *ecdsa.PublicKey:
		hash, err = sig.ECC.HashAlg.Hash()
		if err != nil {
			return err
		}
		if err = verifyECDSAQuoteSignature(pub, hash, quote.Quote, sig); err != nil {
			return err
		}
	case *rsa.PublicKey:
		hash, err = sig.RSA.HashAlg.Hash()
		if err != nil {
			return err
		}
		if err = verifyRSASSAQuoteSignature(pub, hash, quote.Quote, sig); err != nil {
			return err
		}
	default:
		return fmt.Errorf("only RSA and ECC public keys are currently supported, received type: %T", pub)

	}

	// Decode and check for magic TPMS_GENERATED_VALUE.
	attestationData, err := tpm2.DecodeAttestationData(quote.GetQuote())
	if err != nil {
		return fmt.Errorf("decoding attestation data failed: %v", err)
	}
	if attestationData.Type != tpm2.TagAttestQuote {
		return fmt.Errorf("expected quote tag, got: %v", attestationData.Type)
	}
	attestedQuoteInfo := attestationData.AttestedQuoteInfo
	if attestedQuoteInfo == nil {
		return fmt.Errorf("attestation data does not contain quote info")
	}
	if subtle.ConstantTimeCompare(attestationData.ExtraData, extraData) == 0 {
		return fmt.Errorf("quote extraData did not match expected extraData")
	}
	if err := validatePCRDigest(attestedQuoteInfo, pcrs, hash); err != nil {
		return err
	}
	return nil
}

func verifyECDSAQuoteSignature(ecdsaPub *ecdsa.PublicKey, hash crypto.Hash, quoted []byte, sig *tpm2.Signature) error {
	if sig.Alg != tpm2.AlgECDSA {
		return fmt.Errorf("signature scheme 0x%x is not supported, only ECDSA is supported", sig.Alg)
	}

	hashConstructor := hash.New()
	hashConstructor.Write(quoted)
	if !ecdsa.Verify(ecdsaPub, hashConstructor.Sum(nil), sig.ECC.R, sig.ECC.S) {
		return fmt.Errorf("ECC signature verification failed")
	}
	return nil
}

func verifyRSASSAQuoteSignature(rsaPub *rsa.PublicKey, hash crypto.Hash, quoted []byte, sig *tpm2.Signature) error {
	if sig.Alg != tpm2.AlgRSASSA {
		return fmt.Errorf("signature scheme 0x%x is not supported, only RSASSA (PKCS#1 v1.5) is supported", sig.Alg)
	}

	hashConstructor := hash.New()
	hashConstructor.Write(quoted)
	if err := rsa.VerifyPKCS1v15(rsaPub, hash, hashConstructor.Sum(nil), sig.RSA.Signature); err != nil {
		return fmt.Errorf("RSASSA signature verification failed: %v", err)
	}
	return nil
}

func validatePCRDigest(quoteInfo *tpm2.QuoteInfo, pcrs *tpmpb.Pcrs, hash crypto.Hash) error {
	if !client.HasSamePCRSelection(pcrs, quoteInfo.PCRSelection) {
		return fmt.Errorf("given PCRs and Quote do not have the same PCR selection")
	}
	pcrDigest := client.ComputePCRDigest(pcrs, hash)
	if subtle.ConstantTimeCompare(quoteInfo.PCRDigest, pcrDigest) == 0 {
		return fmt.Errorf("given PCRs digest not matching")
	}
	return nil
}
