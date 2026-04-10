package teeserver

import (
	"github.com/GoogleCloudPlatform/confidential-space/server/labels"
	attestationpb "github.com/GoogleCloudPlatform/confidential-space/server/proto/gen/attestation"
)

func dummyHostAttestation(challenge []byte) *attestationpb.HostAttestation {
	return &attestationpb.HostAttestation{
		Label:     []byte(labels.HostAttestation),
		Challenge: challenge,
		ExtraData: []byte("dummy-extra-data"),
		TpmQuote: &attestationpb.TpmQuote{
			Quotes: []*attestationpb.TpmQuote_SignedQuote{
				{
					HashAlgorithm: 11, // TPM_ALG_SHA256
					PcrValues: map[uint32][]byte{
						0:  []byte("/%\235\307QWC\241\004\362\0133\350a\202X\362\n\034\275\001\343}\250\347!2\342F\243\306\234"),
						17: []byte("\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377"),
						18: []byte("\357\2068\010@\307\323i\366){\227\253h\334\240$:\375Q\252G\264\275`>,\0303\335\033B"),
						21: []byte("\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377"),
					},
					TpmsAttest:    []byte("\377TCG\200\030\000\"\000\013\347`Cr-K\321\226\373\341\270S\355\243\306\027=l\321\273\212\255\233\301\355\300\354$\211^.\224\000 ]\033`\314.\001E\247\305\224\245\224\004u\242)\330\267\346\332\215\346\244\027Vx6\350c\377\246z\000\000\000\000\t\326G\350\000\000\000\001\000\000\000\000\000\000\000\000\006x\302\244\027\000\000\000\001\000\013\003\001\000&\000 \272\252\325\271\326$!Q\334\021;\362\267n\377\240\346\204a\212q\234E\344CJ\002O|vN\031"),
					TpmtSignature: []byte("\000\030\000\013\000 sY\303\255!iV\033\331S\346e\254ns\360c\322\226\200\373^)\231\223\204A\212\356)\000N\000 r\211\231\265M\365\376N\230d\264\025 2\232\375\364\331\277}n\364#\332YI@\222\n\016\342\303"),
				},
			},
			PcclientBootEventLog: []byte("dummy_pcclient_event_log"),
			CelLaunchEventLog:    []byte("dummy_cel_launch_event_log"),
		},
		AuxAttestation: &attestationpb.TpmAuxiliaryAttestation{
			SignedNvs: []*attestationpb.TpmAuxiliaryAttestation_SignedNvCertify{
				{
					NvData:        []byte("\000\000\000\000\000\000\000\001"),
					TpmsNvPublic:  []byte("\001\301\000\004\000\013\"\002\000\022\000\000\000\010"),
					TpmsAttest:    []byte("\377TCG\200\024\000\"\000\013\347`Cr-K\321\226\373\341\270S\355\243\306\027=l\321\273\212\255\233\301\355\300\354$\211^.\224\000 ]\033`\314.\001E\247\305\224\245\224\004u\242)\330\267\346\332\215\346\244\027Vx6\350c\377\246z\000\000\000\000\t\326J\375\000\000\000\001\000\000\000\000\000\000\000\000\006x\302\244\027\000\"\000\013,C\204\263\274(\371\350\213\024\034\215\376\323\305\364\023]\343\021\302\004\204r\325\017+)\340\000\217+\000\000\000\010\000\000\000\000\000\000\000\001"),
					TpmtSignature: []byte("\000\030\000\013\000 q\327\330\221\262a\361\277\302A\211\275s`\005\005\324\035\362-<@\017\002B\017\356r\367E\322_\000 \036\304r\232\371kiP\371~\301\020\275\2605P/w;,\204\035\212u\353\223H\016}yY\254"),
				},
			},
		},
	}
}
