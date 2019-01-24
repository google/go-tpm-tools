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
var output = flag.String("out", "", "filename for sealed data destination. Will send to stdout if no filename is specified.")
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

	sensitive, err = ioutil.ReadAll(os.Stdin)
	if err != nil {
		panic(fmt.Errorf("could not stdin: %v", err))
	}

	sealed, err := key.Seal(pcrs, sensitive)
	if err != nil {
		panic(fmt.Errorf("could not seal data: %v", err))
	}

	outBytes, err := proto.Marshal(sealed)
	if err != nil {
		panic(fmt.Errorf("could not marshal pb: %v", err))
	}
	if *output != "" {
		err = ioutil.WriteFile(*output, outBytes, os.FileMode(0666))
		if err != nil {
			panic(fmt.Errorf("could not write output: %v", err))
		}
	} else {
		os.Stdout.Write(outBytes)
	}
}
