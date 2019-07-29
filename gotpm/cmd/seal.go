package cmd

import (
	"fmt"
	"io/ioutil"

	"github.com/golang/protobuf/proto"
	"github.com/spf13/cobra"

	gotpmtoolspb "github.com/google/go-tpm-tools/proto"
	"github.com/google/go-tpm/tpm2"
)

var sealCmd = &cobra.Command{
	Use:   "seal",
	Short: "Seal some data to the TPM",
	Long: `Encrypt the input data using the TPM

TPMs support a "sealing" operation that ... TODO(joerichey): finish`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		rwc, err := openTpm()
		if err != nil {
			return err
		}
		defer rwc.Close()

		fmt.Fprintln(debugOutput(), "Loading SRK")
		srk, err := getSRK(rwc)
		if err != nil {
			return err
		}
		defer srk.Close()

		fmt.Fprintln(debugOutput(), "Reading sealed data")
		secret, err := ioutil.ReadAll(dataInput())
		if err != nil {
			return err
		}

		fmt.Fprintf(debugOutput(), "Sealing to PCRs: %v\n", pcrs)
		sealed, err := srk.Seal(pcrs, secret)
		if err != nil {
			return fmt.Errorf("sealing data: %v", err)
		}

		fmt.Fprintln(debugOutput(), "Writing sealed data")
		if err := proto.MarshalText(dataOutput(), sealed); err != nil {
			return err
		}
		fmt.Fprintf(debugOutput(), "Sealed data to PCRs: %v\n", pcrs)
		return nil
	},
}

var unsealCmd = &cobra.Command{
	Use:   "unseal",
	Short: "Unseal some data previously sealed to the TPM",
	Long: `Decrypt the input data using the TPM

The opposite of "gotpm seal" ... TODO(joerichey): finish`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		rwc, err := openTpm()
		if err != nil {
			return err
		}
		defer rwc.Close()

		fmt.Fprintln(debugOutput(), "Reading sealed data")
		data, err := ioutil.ReadAll(dataInput())
		if err != nil {
			return err
		}
		var sealed gotpmtoolspb.SealedBytes
		if err := proto.UnmarshalText(string(data), &sealed); err != nil {
			return err
		}

		fmt.Fprintln(debugOutput(), "Loading SRK")
		srk, err := getSRKwithAlgo(rwc, tpm2.Algorithm(sealed.GetSrk()))
		if err != nil {
			return err
		}
		defer srk.Close()

		fmt.Fprintln(debugOutput(), "Unsealing data")
		secret, err := srk.Unseal(&sealed)
		if err != nil {
			return fmt.Errorf("unsealing data: %v", err)
		}

		fmt.Fprintln(debugOutput(), "Writing secret data")
		if _, err := dataOutput().Write(secret); err != nil {
			return fmt.Errorf("writing secret data: %v", err)
		}
		fmt.Fprintln(debugOutput(), "Unsealed data using TPM")
		return nil
	},
}

func init() {
	RootCmd.AddCommand(sealCmd)
	RootCmd.AddCommand(unsealCmd)
	addInputFlag(sealCmd)
	addInputFlag(unsealCmd)
	addOutputFlag(sealCmd)
	addOutputFlag(unsealCmd)
	// PCRs only used for sealing
	addPCRsFlag(sealCmd)
	addPublicKeyAlgoFlag(sealCmd)
}
