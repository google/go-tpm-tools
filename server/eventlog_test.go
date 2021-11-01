package server

import (
	"encoding/hex"
	"errors"
	"fmt"
	"testing"

	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm-tools/internal/test"
	pb "github.com/google/go-tpm-tools/proto/tpm"
	"github.com/google/go-tpm/tpm2"
)

type eventLog struct {
	RawLog []byte
	Banks  []*pb.PCRs
}

// Agile Event Log from a RHEL 8 GCE instance with Secure Boot enabled
var Rhel8GCE = eventLog{
	RawLog: test.Rhel8EventLog,
	Banks: []*pb.PCRs{{
		Hash: pb.HashAlgo_SHA1,
		Pcrs: map[uint32][]byte{
			0:  decodeHex("0f2d3a2a1adaa479aeeca8f5df76aadc41b862ea"),
			1:  decodeHex("5cc549378bafaa92e965c7e9c287925cfff33abd"),
			2:  decodeHex("b2a83b0ebf2f8374299a5b2bdfc31ea955ad7236"),
			3:  decodeHex("b2a83b0ebf2f8374299a5b2bdfc31ea955ad7236"),
			4:  decodeHex("7fbe2df30156ca4934109f48d850ab327110f8fa"),
			5:  decodeHex("3258daa13f4cccf245c170481c76e2a4602e5a7b"),
			6:  decodeHex("b2a83b0ebf2f8374299a5b2bdfc31ea955ad7236"),
			7:  decodeHex("d7a632f8990b2171e987041b0a3c69fc1b2a4f27"),
			8:  decodeHex("15aab2077008f8325e7c61ee39fedd7118aad5d7"),
			9:  decodeHex("25de9455ef4e8180b76bbb9bb54a82f9a73abb0a"),
			14: decodeHex("1f5149668c40524e01be9cbc3ad527645943f148"),
		},
	}, {
		Hash: pb.HashAlgo_SHA256,
		Pcrs: map[uint32][]byte{
			0:  decodeHex("24af52a4f429b71a3184a6d64cddad17e54ea030e2aa6576bf3a5a3d8bd3328f"),
			1:  decodeHex("454220afaa80c83c3839f6cccd8b3c88bf4f562316a9dda1121c578c9e005a53"),
			2:  decodeHex("3d458cfe55cc03ea1f443f1562beec8df51c75e14a9fcf9a7234a13f198e7969"),
			3:  decodeHex("3d458cfe55cc03ea1f443f1562beec8df51c75e14a9fcf9a7234a13f198e7969"),
			4:  decodeHex("758a3d35f1b0ff5b135dacd07db0c8132c0ac665d944090d4bf96e66447a245c"),
			5:  decodeHex("53d0ee36163219201e686167bbb71ec505b3ba2917b9d9183ed84aad26cfeb89"),
			6:  decodeHex("3d458cfe55cc03ea1f443f1562beec8df51c75e14a9fcf9a7234a13f198e7969"),
			7:  decodeHex("5fd54361d580eb7592adb8deb236ff35444ceeac7148f24b3de63c041f12b3da"),
			8:  decodeHex("25c3874041ebd4e9a21b6ed71b624a7bfa99907a8dcea7f129a4c64cbaf5829a"),
			9:  decodeHex("d43b2f61eb18b4791812ff5f20ab20e4ef621ba683370bedf5dbdf518b3a8078"),
			14: decodeHex("d8f57ebcc1a23cc46832696e1a657f720e1be8f5b405bb7204682114e363b455"),
		},
	}},
}

// Agile Event Log from a Ubuntu 18.04 GCE instance with Secure Boot and
// Confidential Computing enabled.
var UbuntuAmdSevGCE = eventLog{
	RawLog: test.Ubuntu1804AmdSevEventLog,
	Banks: []*pb.PCRs{{
		Hash: pb.HashAlgo_SHA1,
		Pcrs: map[uint32][]byte{
			0: decodeHex("c032c3b51dbb6f96b047421512fd4b4dfde496f3"),
			1: decodeHex("35f38e5ce90728b02a0f66d836eef53d287e69bf"),
			2: decodeHex("b2a83b0ebf2f8374299a5b2bdfc31ea955ad7236"),
			3: decodeHex("b2a83b0ebf2f8374299a5b2bdfc31ea955ad7236"),
			4: decodeHex("41c68947aeee8a59110c7989a9b7a55df547f003"),
			5: decodeHex("baee22b5cce9029300f909add54d75d5d7475cfd"),
			6: decodeHex("b2a83b0ebf2f8374299a5b2bdfc31ea955ad7236"),
			7: decodeHex("6530ed2dcba68801c78ca08753f239118bead7c8"),
			8: decodeHex("4e5533d878287970f3ef8d374fb140d93bcb2c37"),
			9: decodeHex("1b79f2140a84462cb13d1a0c1904daefd24d7938"),
		},
	}, {
		Hash: pb.HashAlgo_SHA256,
		Pcrs: map[uint32][]byte{
			0: decodeHex("0f35c214608d93c7a6e68ae7359b4a8be5a0e99eea9107ece427c4dea4e439cf"),
			1: decodeHex("add81cbc06b154716ac7bd5999c84cbc520184d57c58102657d270274508d9ce"),
			2: decodeHex("3d458cfe55cc03ea1f443f1562beec8df51c75e14a9fcf9a7234a13f198e7969"),
			3: decodeHex("3d458cfe55cc03ea1f443f1562beec8df51c75e14a9fcf9a7234a13f198e7969"),
			4: decodeHex("b4b94e840fc9352e20bdb5b456b4c242af0fb146755b6935d8eda000ea368a31"),
			5: decodeHex("0b75168095fd6464ff1f9943b762ec009a3ae84c5e76cf67361e16b9db30d28e"),
			6: decodeHex("3d458cfe55cc03ea1f443f1562beec8df51c75e14a9fcf9a7234a13f198e7969"),
			7: decodeHex("61af3f499f1a86be54458fd30d193fa913a7e23ca3103fa3d0abaefd3cd4f9b8"),
			8: decodeHex("c324da9d0c54252c37af697cdd58b066f2bb0f4a69752d27623bc738d02e9486"),
			9: decodeHex("2d334f1eeb9a16dabaccaa746ff1c0dce2e9aeb3f3a4a314e5e1e61b01e940d0"),
		},
	}},
}

// Agile Event Log from a Ubuntu 21.04 GCE instance without a DBX and with Secure Boot disabled
var Ubuntu2104NoDbxGCE = eventLog{
	RawLog: test.Ubuntu2104NoDbxEventLog,
	Banks: []*pb.PCRs{{
		Hash: pb.HashAlgo_SHA1,
		Pcrs: map[uint32][]byte{
			0:  decodeHex("0f2d3a2a1adaa479aeeca8f5df76aadc41b862ea"),
			1:  decodeHex("36c6b7436c37243c5f6744b73ced4df1287cd16a"),
			2:  decodeHex("b2a83b0ebf2f8374299a5b2bdfc31ea955ad7236"),
			3:  decodeHex("b2a83b0ebf2f8374299a5b2bdfc31ea955ad7236"),
			4:  decodeHex("8d9868b66afcf4039eaf8ef5228556d9f313659f"),
			5:  decodeHex("b0eaa45a496e0d933f63e97fd2362192dd48e369"),
			6:  decodeHex("b2a83b0ebf2f8374299a5b2bdfc31ea955ad7236"),
			7:  decodeHex("777795cbdeca679f7749d8d09fc12941dcc9912a"),
			8:  decodeHex("5dfae5320ea06ddd1c62d296844a9b4b32b49972"),
			9:  decodeHex("f53869ab9015b5ad736e5f00e44fdfee2fdfde27"),
			14: decodeHex("cd3734d2bdfcfba9e443ac02c03c812ffcceb255"),
		},
	}, {
		Hash: pb.HashAlgo_SHA256,
		Pcrs: map[uint32][]byte{
			0:  decodeHex("24af52a4f429b71a3184a6d64cddad17e54ea030e2aa6576bf3a5a3d8bd3328f"),
			1:  decodeHex("f7dab5fda6b082e0ec1a12c43dd996ee409111422cda752a784620313039db19"),
			2:  decodeHex("3d458cfe55cc03ea1f443f1562beec8df51c75e14a9fcf9a7234a13f198e7969"),
			3:  decodeHex("3d458cfe55cc03ea1f443f1562beec8df51c75e14a9fcf9a7234a13f198e7969"),
			4:  decodeHex("295aeaeacad1d507930bab18418f905eeda633ea67b2ab94c5e5fd3a4d47ac58"),
			5:  decodeHex("e4f1359accfe48b19af7d38e98a3f373116b55b7f7a6f58f826f409a91d9fd28"),
			6:  decodeHex("3d458cfe55cc03ea1f443f1562beec8df51c75e14a9fcf9a7234a13f198e7969"),
			7:  decodeHex("ca37324eeffabd318d30a20f15bf27ce25dc33e2c9856279ff6c2ced58b02efa"),
			8:  decodeHex("2f2559cae74bb441d75afea5edb78d9a645db9f4bf8dea84bab0861ce6032e18"),
			9:  decodeHex("9f27883322aaaf043662c27542d9685790c687ea554e4e2ae30f0e099a2e4889"),
			14: decodeHex("8351c65483c5419079e8c96758dd2130bee075d71fea226f68ec4eb5bfc71983"),
		},
	}},
}

// Agile Event Log from a Ubuntu 21.04 GCE instance with Secure Boot disabled
var Ubuntu2104NoSecureBootGCE = eventLog{
	RawLog: test.Ubuntu2104NoSecureBootEventLog,
	Banks: []*pb.PCRs{{
		Hash: pb.HashAlgo_SHA1,
		Pcrs: map[uint32][]byte{
			0:  decodeHex("0f2d3a2a1adaa479aeeca8f5df76aadc41b862ea"),
			1:  decodeHex("f5310dfcfcec5571cbf730064d526906c9cea2f0"),
			2:  decodeHex("b2a83b0ebf2f8374299a5b2bdfc31ea955ad7236"),
			3:  decodeHex("b2a83b0ebf2f8374299a5b2bdfc31ea955ad7236"),
			4:  decodeHex("e53d909941dcbc699b273fc4c0d817a41c6ab975"),
			5:  decodeHex("9e2af4bac1432830594b1ae90c68c52a20a9700e"),
			6:  decodeHex("b2a83b0ebf2f8374299a5b2bdfc31ea955ad7236"),
			7:  decodeHex("ede7204673f41ac2592b0d3b4cd429b43f39dc61"),
			8:  decodeHex("bda59abe1c7d18e0b85edfcb4381f10d4dcc88f7"),
			9:  decodeHex("39fd49224476f4d7eea26a53e264c9c33e47649c"),
			14: decodeHex("cd3734d2bdfcfba9e443ac02c03c812ffcceb255"),
		},
	}, {
		Hash: pb.HashAlgo_SHA256,
		Pcrs: map[uint32][]byte{
			0:  decodeHex("24af52a4f429b71a3184a6d64cddad17e54ea030e2aa6576bf3a5a3d8bd3328f"),
			1:  decodeHex("45ed8540f34db53220ef197e5fb8a3835b2095454349e445f397f13d91c509a5"),
			2:  decodeHex("3d458cfe55cc03ea1f443f1562beec8df51c75e14a9fcf9a7234a13f198e7969"),
			3:  decodeHex("3d458cfe55cc03ea1f443f1562beec8df51c75e14a9fcf9a7234a13f198e7969"),
			4:  decodeHex("ebc7ae25d0347868250995c9a8fff16bf79e048453262d0ef2756e213c76181c"),
			5:  decodeHex("47715f9f2c10769da6ee23be5633fd88e247caf162f4eeb0b6f8482ccfeadfb5"),
			6:  decodeHex("3d458cfe55cc03ea1f443f1562beec8df51c75e14a9fcf9a7234a13f198e7969"),
			7:  decodeHex("0d8847bc5eca06452df10e2f214363845c7ac11d47525a5474e225e72ce25dfe"),
			8:  decodeHex("b9a324947de94ec2fd4b04483ecfcb37dfdd520a7c0ecf73c77bf2595549c84f"),
			9:  decodeHex("adb87be3efd96cc3a2f66b8aa7564f9727563ef494a95d571a3f38ff4afb25dd"),
			14: decodeHex("8351c65483c5419079e8c96758dd2130bee075d71fea226f68ec4eb5bfc71983"),
		},
	}},
}

// Agile Event Log from Alex's gLinux laptop with secure boot disabled
var GlinuxNoSecureBootLaptop = eventLog{
	RawLog: test.GlinuxAlexEventLog,
	Banks: []*pb.PCRs{{
		Hash: pb.HashAlgo_SHA1,
		Pcrs: map[uint32][]byte{
			0: decodeHex("29d236609a5f9cc6912af44ba5f57b13a17c8a84"),
			1: decodeHex("db16852a369b2503d6cc6c0007501c837dbe1170"),
			2: decodeHex("0c8ef58d40b8cd1fe15f6b45fc1b385dd251eec0"),
			3: decodeHex("b2a83b0ebf2f8374299a5b2bdfc31ea955ad7236"),
			4: decodeHex("c56cddf3dcf59a473a239efd17b130391e24b0df"),
			5: decodeHex("23606963a2813421f5b6e76e32a337ff8940e413"),
			6: decodeHex("b2a83b0ebf2f8374299a5b2bdfc31ea955ad7236"),
			7: decodeHex("9221b8fc57b60cb7de507dc016f88d4600cde9c5"),
		},
	}, {
		Hash: pb.HashAlgo_SHA256,
		Pcrs: map[uint32][]byte{
			0: decodeHex("0e5ea849d7647a1ac1becc096fee4df98f00f8015f934afadaab0b8aa20b38a5"),
			1: decodeHex("9750400838980c9419764b9cf19c975c0e159c18ebe21cb897c6e834a8d8d433"),
			2: decodeHex("970096d49105b0404999173e49c3f6b8597b9c4c5ff6a9e364b55ce01037578e"),
			3: decodeHex("3d458cfe55cc03ea1f443f1562beec8df51c75e14a9fcf9a7234a13f198e7969"),
			4: decodeHex("ddb124ca9013f1e42f98537f7f381e47c5e6caa988cf2b4088f452c5a8dd912d"),
			5: decodeHex("fb58603615cfec59c0428e71913d30d45f38e4280380cc814135a7659c246b13"),
			6: decodeHex("3d458cfe55cc03ea1f443f1562beec8df51c75e14a9fcf9a7234a13f198e7969"),
			7: decodeHex("9d1be46302bc4f5055c90a0376d9142e397ca8744f387c9824170f1bc855fde5"),
		},
	}},
}

// Agile Event Log from an Arch Linux worksation with systemd-boot and Secure Boot Disabled
var ArchLinuxWorkstation = eventLog{
	RawLog: test.ArchLinuxWorkstationEventLog,
	Banks: []*pb.PCRs{{
		Hash: pb.HashAlgo_SHA1,
		Pcrs: map[uint32][]byte{
			0: decodeHex("a0487b0d95387d4a30560edf5f041307bf4a1dcc"),
			1: decodeHex("56b71c334a5b67d3b7b3343e3241dff5a1ad87bf"),
			2: decodeHex("01098a68e44e4fbd0af3b9a836b1b79e78c4f6f5"),
			3: decodeHex("b2a83b0ebf2f8374299a5b2bdfc31ea955ad7236"),
			4: decodeHex("4c8b6f359b5e5cb9d09e825009a98e1281165b01"),
			5: decodeHex("0dfa5ca60508ac5214515b20ed3e66289514fcb6"),
			6: decodeHex("b2a83b0ebf2f8374299a5b2bdfc31ea955ad7236"),
			7: decodeHex("029c700c2fa2bc83cbf3ce4ee501ad4d984ec5ae"),
			8: decodeHex("aa99fc93faa0777f42da6e1ae77a0653b5005619"),
		},
	}, {
		Hash: pb.HashAlgo_SHA256,
		Pcrs: map[uint32][]byte{
			0: decodeHex("758b773d94feabf52ef5a4c00a7ad2c80d8d6e6d9d58756150be9bc973da9087"),
			1: decodeHex("bfda688a5d320123fddb3fc70b746bc17647e2e7f2f96e130d429542bf4622d5"),
			2: decodeHex("65dee4a48cde677aa89fa83c5c35e883fda658f743853e3ebad504ca6702f7c5"),
			3: decodeHex("3d458cfe55cc03ea1f443f1562beec8df51c75e14a9fcf9a7234a13f198e7969"),
			4: decodeHex("925d453d3dfef4ac0c72c957402163d45fa95d05e6d53f047263a3a60b598325"),
			5: decodeHex("202522f005ef625588bb7c9e21335ba96a63c5086306138885b3bb2c381730ca"),
			6: decodeHex("3d458cfe55cc03ea1f443f1562beec8df51c75e14a9fcf9a7234a13f198e7969"),
			7: decodeHex("3b4a4db44b7a872524055364e62e897ae678e0d47ab0809f65c3a4ed77f66ab9"),
			8: decodeHex("47591b43af431963eaeb5238a5c42eda1eb0014c27f7de7ae483066a2d2a2e61"),
		},
	}},
}

// Legacy Event Log from a Debian 10 GCE instance with Secure Boot enabled
var Debian10GCE = eventLog{
	RawLog: test.Debian10EventLog,
	Banks: []*pb.PCRs{{
		Hash: pb.HashAlgo_SHA1,
		Pcrs: map[uint32][]byte{
			0: decodeHex("0f2d3a2a1adaa479aeeca8f5df76aadc41b862ea"),
			1: decodeHex("b1676439cac1531683990fefe2218a43239d6fe8"),
			2: decodeHex("b2a83b0ebf2f8374299a5b2bdfc31ea955ad7236"),
			3: decodeHex("b2a83b0ebf2f8374299a5b2bdfc31ea955ad7236"),
			4: decodeHex("1eb30816474a3f144e99b24e4ad480b2e51fd9e1"),
			5: decodeHex("019079179dbc0eb5992c500dcf8a095910ac590d"),
			6: decodeHex("b2a83b0ebf2f8374299a5b2bdfc31ea955ad7236"),
			7: decodeHex("9e6c57e850f371c2a7fe02bca552149363952318"),
		},
	}},
}

func TestParseEventLogs(t *testing.T) {
	logs := []struct {
		eventLog
		name string
	}{
		{Debian10GCE, "Debian10GCE"},
		{Rhel8GCE, "Rhel8GCE"},
		{UbuntuAmdSevGCE, "UbuntuAmdSevGCE"},
		{Ubuntu2104NoDbxGCE, "Ubuntu2104NoDbxGCE"},
		{Ubuntu2104NoSecureBootGCE, "Ubuntu2104NoSecureBootGCE"},
		{ArchLinuxWorkstation, "ArchLinuxWorkstation"},
	}

	for _, log := range logs {
		rawLog := log.RawLog
		for _, bank := range log.Banks {
			hashName := pb.HashAlgo_name[int32(bank.Hash)]
			subtestName := fmt.Sprintf("%s-%s", log.name, hashName)
			t.Run(subtestName, func(t *testing.T) {
				if _, err := ParseMachineState(rawLog, bank); err != nil {
					t.Errorf("failed to parse and replay log: %v", err)
				}
			})
		}
	}
}

func TestSystemParseEventLog(t *testing.T) {
	rwc := test.GetTPM(t)
	defer client.CheckedClose(t, rwc)

	evtLog, err := client.GetEventLog(rwc)
	if err != nil {
		t.Fatalf("failed to retrieve Event Log: %v", err)
	}

	sel := client.FullPcrSel(tpm2.AlgSHA1)
	pcrs, err := client.ReadPCRs(rwc, sel)
	if err != nil {
		t.Fatalf("failed to read PCRs: %v", err)
	}

	if _, err = ParseMachineState(evtLog, pcrs); err != nil {
		t.Errorf("failed to parse and replay log: %v", err)
	}
}

func decodeHex(hexStr string) []byte {
	bytes, err := hex.DecodeString(hexStr)
	if err != nil {
		panic(err)
	}
	return bytes
}
