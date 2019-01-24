package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"strconv"
	"strings"

	"github.com/golang/protobuf/proto"
	"github.com/google/go-tpm-tools/tpm2tools"
	"github.com/google/go-tpm/tpm2"
)

type pcrList []int

func (pcrs *pcrList) String() string {
	s := make([]string, len(*pcrs))
	for i, pcr := range *pcrs {
		s[i] = string(pcr)
	}
	return strings.Join(s, ",")
}

func (pcrs *pcrList) Set(value string) error {
	pcr, err := strconv.Atoi(value)
	if err != nil {
		return fmt.Errorf("failed to parse pcr from flags: %v", err)
	}
	*pcrs = append(*pcrs, pcr)
	return nil
}

var tpmPath = flag.String("tpm_path", "/dev/tpmrm0", "location of the tpm device in the filesystem.")
var input = flag.String("input", "", "filename for sealed data destination. Will send to stdout if no filename is specified.")
var pcrs pcrList

func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func main() {
	flag.Var(&pcrs, "pcr", "tpm pcrs to be sealed against. May be repeated.")
	flag.Parse()
	var sensitive []byte
	defer zeroBytes(sensitive)

	tpm, err := tpm2.OpenTPM(*tpmPath)
	if err != nil {
		panic(fmt.Errorf("Failed to open tpm: %v", err))
	}

	key, err := tpm2tools.StorageRootKeyRSA(tpm)
	if err != nil {
		panic(fmt.Errorf("can't create srk from template: %v", err))
	}
	defer key.Close()

	var in []byte
	if *input != "" {
		in, err = ioutil.ReadFile(*input)
		if err != nil {
			panic(fmt.Errorf("could not read input: %v", err))
		}
	} else {
		in, err = ioutil.ReadAll(os.Stdin)
		if err != nil {
			panic(fmt.Errorf("could not stdin: %v", err))
		}
	}

	inputBytes := tpm2tools.SealedBytes{}
	if err := proto.Unmarshal(in, &inputBytes); err != nil {
		panic(fmt.Errorf("could not unmarshal sealed bytes: %v", err))
	}

	sensitive, err = key.Unseal(pcrs, &inputBytes)
	if err != nil {
		panic(fmt.Errorf("could not seal data: %v", err))
	}

	os.Stdout.Write(sensitive)
}
