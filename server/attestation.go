package server

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"errors"
	"fmt"

	"github.com/google/go-tpm/tpm2"
)

// VerifyOpts enables optional Verify functionality based on
// how the caller wants to verify the AK pub.
type VerifyOpts interface {
}

type TrustedKeyOpt struct {
	trustedKey crypto.PublicKey
}

func (t TrustedKeyOpt) Equals(akPubArea []byte) error {
	tpm2Public, err := tpm2.DecodePublic(akPubArea)
	if err != nil {
		return fmt.Errorf("failed to decode attestation's AK pub: %v", err)
	}
	akKey, err := tpm2Public.Key()
	if err != nil {
		return fmt.Errorf("failed to retrieve public key from AK pub Area: %v", err)
	}
	switch val := akKey.(type) {
	case *rsa.PublicKey:
	case *ecdsa.PublicKey:
		if !val.Equal(t.trustedKey) {
			return errors.New("failed to match attestation's AK pub with trusted key")
		}
	default:
		return fmt.Errorf("key type %T not supported", val)
	}
	return nil
}

// Verify checks that the Attestation message is valid against a Policy:
// - AK pub is trustworthy, via an opts parameter.
// - Quote signature, verified with the AKPub
// - Quote data, against quote signature
// - PCRs match the quote data
// - extraData matches quote data
// - Event log is parsable
// - Event log replays against the PCR digests
//   - Verify will replay the event log against all quotes in the attestation
//     until it finds a successful replay.
//   - If the policy provides UntrustedHashAlgos, Verify will skip the given HashAlgos
//     (this is typically SHA1).
// - Policy applied successfully against event log contents
// Verify returns the MachineState representation from the event log.
//
// Note that the RawEvents in MachineState may not be trustworthy.
// Specifically, the event log's event type cannot be trusted. It should only be
// used as a hint for parsing or debugging.
func VerifyAttestation(attestation *tpmpb.Attestation, policy *tpmpb.AttestationPolicy, opts VerifyOpts) (*tpmpb.MachineState, error) {
	if opts == nil {
		return nil, errors.New("invalid argument: opts cannot be nil")
	}
	switch o := opts.(type) {
	case TrustedKeyOpt:
		if err := o.Equals(attestation.AkPub); err != nil {
			return nil, fmt.Errorf("failed to verify trusted key: %v", err)
		}
	default:
		return nil, errors.New("invalid argument: unknown opts type")
	}

	for i, quote := range attestation.Quotes {
		if err := quote.Verify(attestation.AkPub, extraData); err != nil {
			return nil, fmt.Errorf("failed to verify quote with index %v in attestation", i)
		}
	}

	hashToQuote, err := quotesByHashAlgo(attestation.Quotes)
	if err != nil {
		return nil, err
	}

	var machineState *tpmpb.MachineState
	for hashAlgo, quote := range hashToQuote {
		if contains(policy.UntrustedHashAlgos, hashAlgo) {
			continue
		}

		machineState, err = GetMachineState(attestation.EventLog, quote.Pcrs)
		if err != nil {
			return nil, fmt.Errorf("failed to get MachineState from attestation: %v", err)
		}
	}

	policyCheckOutput := ApplyAttestationPolicy(policy, machineState)
	if len(policyCheckOutput.Errors) != 0 {
		return nil, fmt.Errorf("failed to apply policy to attestation, received errors: %v", policyCheckOutput.Errors)
	}

	return machineState, nil
}

func contains(algos []tpmpb.HashAlgo, toFind tpmpb.HashAlgo) bool {
	for _, algo := range algos {
		if toFind == algo {
			return true
		}
	}
	return false
}

func quotesByHashAlgo(quotes []*tpmpb.Quote) (map[tpmpb.HashAlgo]*tpmpb.Quote, error) {
	hashToQuote := make(map[tpmpb.HashAlgo]*tpmpb.Quote, len(quotes))
	for _, quote := range quotes {
		if quote == nil || quote.Pcrs == nil {
			return nil, errors.New("attestation message contains invalid quote")
		}
		hashToQuote[quote.Pcrs.Hash] = quote
	}
	return hashToQuote, nil
}
