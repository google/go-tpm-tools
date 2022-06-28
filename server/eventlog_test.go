package server

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-tpm-tools/cel"
	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm-tools/internal/test"
	attestpb "github.com/google/go-tpm-tools/proto/attest"
	pb "github.com/google/go-tpm-tools/proto/tpm"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
	"google.golang.org/protobuf/testing/protocmp"
)

type eventLog struct {
	RawLog []byte
	Banks  []*pb.PCRs
}

var archLinuxBadSecureBoot = "SecureBoot data len is 0, expected 1"

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

// Agile Event Log from a Ubuntu 21.04 GCE instance with Secure Boot disabled
var COS85AmdSev = eventLog{
	RawLog: test.Cos85AmdSevEventLog,
	Banks: []*pb.PCRs{{
		Hash: pb.HashAlgo_SHA1,
		Pcrs: map[uint32][]byte{
			0: decodeHex("c032c3b51dbb6f96b047421512fd4b4dfde496f3"),
			1: decodeHex("e3e9e1d9deacd95b289bbbd3a1717a57af7d211b"),
			2: decodeHex("b2a83b0ebf2f8374299a5b2bdfc31ea955ad7236"),
			3: decodeHex("b2a83b0ebf2f8374299a5b2bdfc31ea955ad7236"),
			4: decodeHex("6168c9ce88a8658920f2cf2f9012d3c6bbfab79b"),
			5: decodeHex("fb6b3a15b220a74b0c4f73416919476702e930e2"),
			6: decodeHex("b2a83b0ebf2f8374299a5b2bdfc31ea955ad7236"),
			7: decodeHex("42e669233f0e826df5093abfd6998c020df2de88"),
			8: decodeHex("72778b0ba3c491db25eb7c8368cb1fb51f0ce458"),
			9: decodeHex("08bd04f0dbadf591510340d94a0019c0ddcb779f"),
		},
	}, {
		Hash: pb.HashAlgo_SHA256,
		Pcrs: map[uint32][]byte{
			0: decodeHex("0f35c214608d93c7a6e68ae7359b4a8be5a0e99eea9107ece427c4dea4e439cf"),
			1: decodeHex("6eb40f5b6bfafcb9914d486ce59404acd24bc13a6a3c45cda3b44c9d7053d638"),
			2: decodeHex("3d458cfe55cc03ea1f443f1562beec8df51c75e14a9fcf9a7234a13f198e7969"),
			3: decodeHex("3d458cfe55cc03ea1f443f1562beec8df51c75e14a9fcf9a7234a13f198e7969"),
			4: decodeHex("d690bdac2aa8b73a1d718cb91990df07d0747b07ea57b3b2d0f0d511f0d90491"),
			5: decodeHex("e9e0b32564b6f8215b1bd43954d9f910682d39c3b18abd4737ac3b797cf269e0"),
			6: decodeHex("3d458cfe55cc03ea1f443f1562beec8df51c75e14a9fcf9a7234a13f198e7969"),
			7: decodeHex("3365d7fa2b024c852913c06e04ffbfa6ea5289f743bbf1a76f7ffdf21ed84793"),
			8: decodeHex("9e9b6511ae6ad443aae4c7bf998ffffbcd271c874f1efab9d692f129eb6e6c18"),
			9: decodeHex("f4f2d92d6d54f6c41f2706fd98091317642e0680a7902c72893d41e3464a93b7"),
		},
	}},
}

var COS93AmdSev = eventLog{
	RawLog: test.Cos93AmdSevEventLog,
	Banks: []*pb.PCRs{{
		Hash: pb.HashAlgo_SHA1,
		Pcrs: map[uint32][]byte{
			0: decodeHex("c032c3b51dbb6f96b047421512fd4b4dfde496f3"),
			1: decodeHex("e3e9e1d9deacd95b289bbbd3a1717a57af7d211b"),
			2: decodeHex("b2a83b0ebf2f8374299a5b2bdfc31ea955ad7236"),
			3: decodeHex("b2a83b0ebf2f8374299a5b2bdfc31ea955ad7236"),
			4: decodeHex("1e4b998edfb4d62fb88337a66b3af8be26159498"),
			5: decodeHex("3421f02e05d71fe4bd002cbe22e68c230397821d"),
			6: decodeHex("b2a83b0ebf2f8374299a5b2bdfc31ea955ad7236"),
			7: decodeHex("42e669233f0e826df5093abfd6998c020df2de88"),
			8: decodeHex("ec84952e0c5c96cd4404122131b8f86d5ac7df7d"),
			9: decodeHex("7a406f847075a86a55aa184cfe3fcef7eaff40a7"),
		},
	}, {
		Hash: pb.HashAlgo_SHA256,
		Pcrs: map[uint32][]byte{
			0: decodeHex("0f35c214608d93c7a6e68ae7359b4a8be5a0e99eea9107ece427c4dea4e439cf"),
			1: decodeHex("6eb40f5b6bfafcb9914d486ce59404acd24bc13a6a3c45cda3b44c9d7053d638"),
			2: decodeHex("3d458cfe55cc03ea1f443f1562beec8df51c75e14a9fcf9a7234a13f198e7969"),
			3: decodeHex("3d458cfe55cc03ea1f443f1562beec8df51c75e14a9fcf9a7234a13f198e7969"),
			4: decodeHex("871e8343044ae4c87b402dcb94b5e49715b1b8dc1b19c43ba0801422fabb39d4"),
			5: decodeHex("74be59dc8066011eade913db9a3db7978f93852c04816cba9427dd59b87042cc"),
			6: decodeHex("3d458cfe55cc03ea1f443f1562beec8df51c75e14a9fcf9a7234a13f198e7969"),
			7: decodeHex("3365d7fa2b024c852913c06e04ffbfa6ea5289f743bbf1a76f7ffdf21ed84793"),
			8: decodeHex("ba18b7028111f1f193967cad3c23b5050f73061c0f119182ac0f42efd6a9159e"),
			9: decodeHex("0b1e4f9ca7bc8535c4c33f0025969d7abea008aa51dcd7f7c2d1068470e4bce4"),
		},
	}},
}

func TestParseEventLogs(t *testing.T) {
	sbatErrorStr := "asn1: structure error: tags don't match (16 vs {class:0 tag:24 length:10 isCompound:true})"
	logs := []struct {
		eventLog
		name string
		Bootloader
		// This field handles known issues with event log parsing or bad event
		// logs.
		// An empty string will not attempt to pattern match the error result.
		errorSubstr string
	}{
		{Debian10GCE, "Debian10GCE", UnsupportedLoader, ""},
		{Rhel8GCE, "Rhel8GCE", GRUB, ""},
		{UbuntuAmdSevGCE, "UbuntuAmdSevGCE", GRUB, ""},
		// TODO: remove once the fix is pulled in
		// https://github.com/google/go-attestation/pull/222
		{Ubuntu2104NoDbxGCE, "Ubuntu2104NoDbxGCE", GRUB, sbatErrorStr},
		{Ubuntu2104NoSecureBootGCE, "Ubuntu2104NoSecureBootGCE", GRUB, sbatErrorStr},
		// This event log has a SecureBoot variable length of 0.
		{ArchLinuxWorkstation, "ArchLinuxWorkstation", UnsupportedLoader, archLinuxBadSecureBoot},
		{COS85AmdSev, "COS85AmdSev", GRUB, ""},
		{COS93AmdSev, "COS93AmdSev", GRUB, ""},
	}

	for _, log := range logs {
		rawLog := log.RawLog
		for _, bank := range log.Banks {
			hashName := pb.HashAlgo_name[int32(bank.Hash)]
			subtestName := fmt.Sprintf("%s-%s", log.name, hashName)
			t.Run(subtestName, func(t *testing.T) {
				if _, err := parsePCClientEventLog(rawLog, bank, UnsupportedLoader); err != nil {
					gErr, ok := err.(*GroupedError)
					if !ok {
						t.Errorf("ParseMachineState should return a GroupedError")
					}
					if log.errorSubstr == "" {
						t.Errorf("expected no errors in GroupedError, received (%v)", err)
					}
					if !gErr.containsOnlySubstring(log.errorSubstr) {
						t.Errorf("failed to parse and replay log: %v", err)
					}
				}
			})
		}
	}
}

func TestParseMachineStateReplayFail(t *testing.T) {
	badPcrs := pb.PCRs{Hash: pb.HashAlgo_SHA1}
	pcrMap := make(map[uint32][]byte)
	pcrMap[0] = []byte{0, 0, 0, 0}
	badPcrs.Pcrs = pcrMap

	_, err := parsePCClientEventLog(Debian10GCE.RawLog, &badPcrs, UnsupportedLoader)
	if err == nil {
		t.Errorf("ParseMachineState should fail to replay the event log")
	}
	_, ok := err.(*GroupedError)
	if !ok {
		t.Errorf("ParseMachineState should return a GroupedError")
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

	if _, err = parsePCClientEventLog(evtLog, pcrs, UnsupportedLoader); err != nil {
		t.Errorf("failed to parse MachineState: %v", err)
	}
}

func TestEmptyEventlog(t *testing.T) {
	emptyLog := []byte{}
	emptyState := &attestpb.MachineState{
		Hash:       pb.HashAlgo_SHA1,
		Platform:   &attestpb.PlatformState{Firmware: &attestpb.PlatformState_ScrtmVersionId{}},
		SecureBoot: &attestpb.SecureBootState{},
	}

	// SHA-1 PCR data consisting of all zero digests (i.e. the reset state)
	zeroDigest := make([]byte, crypto.SHA1.Size())
	zeroPCRs := &pb.PCRs{Hash: pb.HashAlgo_SHA1, Pcrs: make(map[uint32][]byte)}
	for i := uint32(0); i < 24; i++ {
		zeroPCRs.Pcrs[i] = zeroDigest
	}

	// For our "Real" PCR data, use the simulated TPM (which has extended events)
	rwc := test.GetTPM(t)
	defer client.CheckedClose(t, rwc)
	realPCRs, err := client.ReadPCRs(rwc, client.FullPcrSel(tpm2.AlgSHA1))
	if err != nil {
		t.Fatalf("failed to read PCRs: %v", err)
	}

	cases := []struct {
		name string
		pcrs *pb.PCRs
	}{
		{"Empty", &pb.PCRs{Hash: pb.HashAlgo_SHA1}},
		{"AllZero", zeroPCRs},
		{"Real", realPCRs},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			state, err := parsePCClientEventLog(emptyLog, c.pcrs, UnsupportedLoader)
			if err != nil {
				t.Errorf("parsing empty eventlog: %v", err)
			}
			if diff := cmp.Diff(state, emptyState, protocmp.Transform(), protocmp.IgnoreEmptyMessages()); diff != "" {
				t.Errorf("unexpected non-empty MachineState:\n%v", diff)
			}
		})
	}
}

func TestParseSecureBootState(t *testing.T) {
	for _, bank := range UbuntuAmdSevGCE.Banks {
		msState, err := parsePCClientEventLog(UbuntuAmdSevGCE.RawLog, bank, UnsupportedLoader)
		if err != nil {
			t.Errorf("failed to parse and replay log: %v", err)
		}
		containsWinProdPCA := false
		contains3PUEFI := false
		if len(msState.GetSecureBoot().GetDb().GetHashes()) != 0 {
			t.Error("found hashes in db")
		}
		for _, cert := range msState.GetSecureBoot().GetDb().GetCerts() {
			switch c := cert.GetRepresentation().(type) {
			case *attestpb.Certificate_WellKnown:
				if c.WellKnown == attestpb.WellKnownCertificate_UNKNOWN {
					t.Error(("found WellKnownCertificate_UNKNOWN in db"))
				}
				if c.WellKnown == attestpb.WellKnownCertificate_MS_THIRD_PARTY_UEFI_CA_2011 {
					contains3PUEFI = true
				} else if c.WellKnown == attestpb.WellKnownCertificate_MS_WINDOWS_PROD_PCA_2011 {
					containsWinProdPCA = true
				}
			}
		}
		if !contains3PUEFI || !containsWinProdPCA {
			t.Error("expected to see both WinProdPCA and ThirdPartyUEFI certs")
		}
	}
}

func TestParsingCELEventLog(t *testing.T) {
	tpm := test.GetTPM(t)
	defer client.CheckedClose(t, tpm)

	err := tpm2.PCRReset(tpm, tpmutil.Handle(test.DebugPCR))
	if err != nil {
		t.Fatal(err)
	}

	coscel := &cel.CEL{}
	emptyCosState := attestpb.ContainerState{}

	var buf bytes.Buffer
	// First, encode an empty CEL and try to parse it.
	if err := coscel.EncodeCEL(&buf); err != nil {
		t.Fatal(err)
	}
	banks, err := client.ReadAllPCRs(tpm)
	if err != nil {
		t.Fatal(err)
	}

	implmentedHash := []crypto.Hash{}
	// get all implmented hash algo in the TPM
	for _, h := range banks {
		hsh, err := tpm2.Algorithm(h.Hash).Hash()
		if err != nil {
			t.Fatal(err)
		}
		implmentedHash = append(implmentedHash, crypto.Hash(hsh))
	}

	for _, bank := range banks {
		// pcrs can have any value here, since the coscel has no records, the replay should always success.
		msState, err := parseCanonicalEventLog(buf.Bytes(), bank)
		if err != nil {
			t.Errorf("expecting no error from parseCanonicalEventLog(), but get %v", err)
		}
		if diff := cmp.Diff(msState.Cos.Container, &emptyCosState, protocmp.Transform()); diff != "" {
			t.Errorf("unexpected difference:\n%v", diff)
		}
	}

	// Secondly, append a random non-COS event, encode and try to parse it. Because there is no COS TLV event,
	// we should get an empty/default CosState in the MachineState.
	event, err := generateNonCosCelEvent(implmentedHash)
	if err != nil {
		t.Fatal(err)
	}
	coscel.Records = append(coscel.Records, event)
	buf = bytes.Buffer{}
	if err := coscel.EncodeCEL(&buf); err != nil {
		t.Fatal(err)
	}
	// extend digests to the PCR
	for _, hash := range implmentedHash {
		algo, err := tpm2.HashToAlgorithm(hash)
		if err != nil {
			t.Fatal(err)
		}
		if err := tpm2.PCRExtend(tpm, tpmutil.Handle(test.DebugPCR), algo, event.Digests[hash], ""); err != nil {
			t.Fatal(err)
		}
	}
	banks, err = client.ReadAllPCRs(tpm)
	if err != nil {
		t.Fatal(err)
	}
	for _, bank := range banks {
		msState, err := parseCanonicalEventLog(buf.Bytes(), bank)
		if err != nil {
			t.Errorf("expecting no error from parseCanonicalEventLog(), but get %v", err)
		}
		// expect nothing in the CosState
		if diff := cmp.Diff(msState.Cos.Container, &emptyCosState, protocmp.Transform()); diff != "" {
			t.Errorf("unexpected difference:\n%v", diff)
		}
	}

	// Thirdly, append some real COS events to the CEL. This time we should get content in the CosState.
	testCELEvents := []struct {
		cosNestedEventType cel.CosType
		pcr                int
		eventPayload       []byte
	}{
		{cel.ImageRefType, test.DebugPCR, []byte("docker.io/bazel/experimental/test:latest")},
		{cel.ImageDigestType, test.DebugPCR, []byte("sha256:781d8dfdd92118436bd914442c8339e653b83f6bf3c1a7a98efcfb7c4fed7483")},
		{cel.RestartPolicyType, test.DebugPCR, []byte(attestpb.RestartPolicy_Always.String())},
		{cel.ImageIDType, test.DebugPCR, []byte("sha256:5DF4A1AC347DCF8CF5E9D0ABC04B04DB847D1B88D3B1CC1006F0ACB68E5A1F4B")},
		{cel.EnvVarType, test.DebugPCR, []byte("foo=bar")},
		{cel.EnvVarType, test.DebugPCR, []byte("bar=baz")},
		{cel.EnvVarType, test.DebugPCR, []byte("baz=foo=bar")},
		{cel.EnvVarType, test.DebugPCR, []byte("empty=")},
		{cel.ArgType, test.DebugPCR, []byte("--x")},
		{cel.ArgType, test.DebugPCR, []byte("--y")},
		{cel.ArgType, test.DebugPCR, []byte("")},
	}

	expectedEnvVars := make(map[string]string)
	expectedEnvVars["foo"] = "bar"
	expectedEnvVars["bar"] = "baz"
	expectedEnvVars["baz"] = "foo=bar"
	expectedEnvVars["empty"] = ""

	want := attestpb.ContainerState{
		ImageReference: string(testCELEvents[0].eventPayload),
		ImageDigest:    string(testCELEvents[1].eventPayload),
		RestartPolicy:  attestpb.RestartPolicy_Always,
		ImageId:        string(testCELEvents[3].eventPayload),
		EnvVars:        expectedEnvVars,
		Args:           []string{string(testCELEvents[8].eventPayload), string(testCELEvents[9].eventPayload), string(testCELEvents[10].eventPayload)},
	}
	for _, testEvent := range testCELEvents {
		cos := cel.CosTlv{EventType: testEvent.cosNestedEventType, EventContent: testEvent.eventPayload}
		if err := coscel.AppendEvent(tpm, testEvent.pcr, implmentedHash, cos); err != nil {
			t.Fatal(err)
		}
	}
	buf = bytes.Buffer{}
	if err := coscel.EncodeCEL(&buf); err != nil {
		t.Fatal(err)
	}
	banks, err = client.ReadAllPCRs(tpm)
	if err != nil {
		t.Fatal(err)
	}
	for _, bank := range banks {
		if msState, err := parseCanonicalEventLog(buf.Bytes(), bank); err != nil {
			t.Errorf("expecting no error from parseCanonicalEventLog(), but get %v", err)
		} else {
			if diff := cmp.Diff(msState.Cos.Container, &want, protocmp.Transform()); diff != "" {
				t.Errorf("unexpected difference:\n%v", diff)
			}
		}
	}
}

func generateNonCosCelEvent(hashAlgoList []crypto.Hash) (cel.Record, error) {
	randRecord := cel.Record{}
	randRecord.RecNum = 0
	randRecord.PCR = uint8(test.DebugPCR)
	contentValue := make([]byte, 10)
	rand.Read(contentValue)
	randRecord.Content = cel.TLV{Type: 250, Value: contentValue}
	contentBytes, err := randRecord.Content.MarshalBinary()
	if err != nil {
		return cel.Record{}, err
	}

	digestMap := make(map[crypto.Hash][]byte)
	for _, hash := range hashAlgoList {
		h := hash.New()
		h.Write(contentBytes)
		digestMap[hash] = h.Sum(nil)
	}
	randRecord.Digests = digestMap

	return randRecord, nil
}

func TestParseGrubState(t *testing.T) {
	logs := []struct {
		eventLog
		name string
	}{
		{COS85AmdSev, "COS85AmdSev"},
		{COS93AmdSev, "COS93AmdSev"},
	}
	for _, log := range logs {
		for _, bank := range log.Banks {
			hashName := pb.HashAlgo_name[int32(bank.Hash)]
			subtestName := fmt.Sprintf("COS85AmdSev-%s", hashName)
			t.Run(subtestName, func(t *testing.T) {
				msState, err := parsePCClientEventLog(log.RawLog, bank, GRUB)
				if err != nil {
					t.Errorf("failed to parse and replay log: %v", err)
				}

				if len(msState.Grub.GetCommands()) == 0 {
					t.Errorf("expected COS85 to run GRUB commands!")
				}
				if len(msState.Grub.GetFiles()) != 2 {
					t.Errorf("expected COS85 to read two files (grub.cfg and kernel)!")
				}
			})
		}
	}
}

func TestParseGrubStateFail(t *testing.T) {
	// No GRUB measurements for this event log.
	eventlog := GlinuxNoSecureBootLaptop
	for _, bank := range eventlog.Banks {
		hashName := pb.HashAlgo_name[int32(bank.Hash)]
		subtestName := fmt.Sprintf("GlinuxNoSecureBootLaptop-%s", hashName)
		t.Run(subtestName, func(t *testing.T) {
			_, err := parsePCClientEventLog(eventlog.RawLog, bank, GRUB)
			if err == nil {
				t.Error("expected error when parsing GRUB state")
			}
			gErr, ok := err.(*GroupedError)
			if !ok {
				t.Errorf("ParseMachineState should return a GroupedError")
			}
			if !gErr.containsSubstring("no GRUB measurements found") {
				t.Errorf("expected GroupedError (%s) to contain no GRUB measurements error", err)
			}
		})
	}
}

func decodeHex(hexStr string) []byte {
	bytes, err := hex.DecodeString(hexStr)
	if err != nil {
		panic(err)
	}
	return bytes
}
