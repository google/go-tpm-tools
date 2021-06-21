package server

import (
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"testing"

	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm-tools/internal"
	tpmpb "github.com/google/go-tpm-tools/proto"
	"github.com/google/go-tpm/tpm2"
)

func TestParseCryptoAgileEventLog(t *testing.T) {
	evtLog, err := readEventLog("./test/ubuntu-2104-event-log")
	if err != nil {
		t.Fatalf("failed reading event log: %v", err)
	}

	// Fetched from the tpm2-tools eventlog command.
	sha1Pcrs := tpmpb.Pcrs{
		Hash: tpmpb.HashAlgo_SHA1,
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
	}
	sha256Pcrs := tpmpb.Pcrs{
		Hash: tpmpb.HashAlgo_SHA256,
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
	}
	banks := []*tpmpb.Pcrs{
		&sha1Pcrs,
		&sha256Pcrs,
	}

	for _, bank := range banks {
		_, err = ParseAndVerifyEventLog(evtLog, bank)
		if err != nil {
			t.Errorf("failed to parse and verify log for hash %s: %v",
				tpmpb.HashAlgo_name[int32(bank.Hash)], err)
		}
	}
}

func TestParseSHA1EventLog(t *testing.T) {
	evtLog, err := readEventLog("./test/debian_10_binary_bios_measurements")
	if err != nil {
		t.Fatalf("failed reading event log: %v", err)
	}

	// Fetched from the tpm2-tools eventlog command.
	pcrs := tpmpb.Pcrs{
		Hash: tpmpb.HashAlgo_SHA1,
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
	}

	_, err = ParseAndVerifyEventLog(evtLog, &pcrs)
	if err != nil {
		t.Errorf("failed to parse and verify log: %v", err)
	}
}

func readEventLog(filePath string) ([]byte, error) {
	absPath, err := filepath.Abs(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to get abs path: %v", err)
	}
	evtLog, err := ioutil.ReadFile(absPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read event log: %v", err)
	}
	return evtLog, nil
}

func TestSystemParseEventLog(t *testing.T) {
	rwc := internal.GetTPM(t)
	defer client.CheckedClose(t, rwc)

	evtLog, err := client.GetEventLog(rwc)
	if err != nil {
		t.Fatalf("failed to retrieve Event Log: %v", err)
	}

	sel := client.FullPcrSel(tpm2.AlgSHA1)
	pcrs, err := client.ReadPCRs(rwc, sel)
	if err != nil {
		t.Errorf("failed to read PCRs: %v", err)
	}

	_, err = ParseAndVerifyEventLog(evtLog, pcrs)
	if err != nil {
		t.Errorf("failed to parse and verify log: %v", err)
	}
}

func decodeHex(hexStr string) []byte {
	bytes, err := hex.DecodeString(hexStr)
	if err != nil {
		panic(err)
	}
	return bytes
}
