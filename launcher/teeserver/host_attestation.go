package teeserver

import (
	"github.com/GoogleCloudPlatform/confidential-space/server/labels"
	attestationpb "github.com/GoogleCloudPlatform/confidential-space/server/proto/gen/attestation"
	tspb "github.com/google/go-tpm-tools/launcher/teeserver/proto/gen/teeserver"
)

func dummyHostAttestation(challenge []byte) *tspb.GetHostAttestationResponse {
	return &tspb.GetHostAttestationResponse{
		HostAttestation: &attestationpb.HostAttestation{
			Label:     []byte(labels.HostAttestation),
			Challenge: challenge,
			ExtraData: []byte("dummy-extra-data"),
			TpmQuote: &attestationpb.TpmQuote{
				Quotes: []*attestationpb.TpmQuote_SignedQuote{
					{
						HashAlgorithm: 11, // TPM_ALG_SHA256
						PcrValues: map[uint32][]byte{
							0: []byte("dummy-pcr0"),
							7: []byte("dummy-pcr7"),
						},
						TpmsAttest:    []byte("dummy-tpms-attest"),
						TpmtSignature: []byte("dummy-tpmt-signature"),
					},
				},
				PcclientBootEventLog: []byte("dummy-pcclient-event-log"),
				CelLaunchEventLog:    []byte("dummy-cel-event-log"),
				Endorsement: &attestationpb.TpmAttestationEndorsement{
					Endorsement: &attestationpb.TpmAttestationEndorsement_AkCertEndorsement_{
						AkCertEndorsement: &attestationpb.TpmAttestationEndorsement_AkCertEndorsement{
							AkCert:      []byte("dummy-ak-cert"),
							AkCertChain: [][]byte{[]byte("dummy-ak-cert-chain")},
						},
					},
				},
			},
			AuxAttestation: &attestationpb.TpmAuxiliaryAttestation{
				SignedNvs: []*attestationpb.TpmAuxiliaryAttestation_SignedNvCertify{
					{
						HashAlgorithm: 11, // TPM_ALG_SHA256
						NvData:        []byte("dummy-nv-data"),
						TpmsNvPublic:  []byte("dummy-tpms-nv-public"),
						TpmsAttest:    []byte("dummy-aux-tpms-attest"),
						TpmtSignature: []byte("dummy-aux-tpmt-signature"),
					},
				},
				Endorsement: &attestationpb.TpmAttestationEndorsement{
					Endorsement: &attestationpb.TpmAttestationEndorsement_AkCertEndorsement_{
						AkCertEndorsement: &attestationpb.TpmAttestationEndorsement_AkCertEndorsement{
							AkCert:      []byte("dummy-aux-ak-cert"),
							AkCertChain: [][]byte{[]byte("dummy-aux-ak-cert-chain")},
						},
					},
				},
			},
		},
	}
}
