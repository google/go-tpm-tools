package client

import (
	"errors"
	"fmt"

	pb "github.com/google/go-tpm-tools/proto/attest"
)

// AttestOpts allows for optional Attest functionality to be enabled.
type AttestOpts interface{}

// Attest generates an Attestation containing the TCG Event Log and a Quote over
// all PCR banks. The provided nonce can be used to guarantee freshness of the
// attestation. This function will return an error if the key is not a
// restricted signing key.
//
// An optional AttestOpts can also be passed. Currently, this parameter must be nil.
func (k *Key) Attest(nonce []byte, opts AttestOpts) (*pb.Attestation, error) {
	if opts != nil {
		return nil, errors.New("provided AttestOpts must be nil")
	}
	sels, err := implementedPCRs(k.rw)
	if err != nil {
		return nil, err
	}

	attestation := pb.Attestation{}
	if attestation.AkPub, err = k.PublicArea().Encode(); err != nil {
		return nil, fmt.Errorf("failed to encode public area: %w", err)
	}
	for _, sel := range sels {
		quote, err := k.Quote(sel, nonce)
		if err != nil {
			return nil, err
		}
		attestation.Quotes = append(attestation.Quotes, quote)
	}
	if attestation.EventLog, err = GetEventLog(k.rw); err != nil {
		return nil, fmt.Errorf("failed to retrieve TCG Event Log: %w", err)
	}
	return &attestation, nil
}
