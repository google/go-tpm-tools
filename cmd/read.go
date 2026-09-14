package cmd

import (
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm-tools/internal"
	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
	"github.com/spf13/cobra"
)

var readCmd = &cobra.Command{
	Use:   "read <pcr>",
	Short: "Read from the TPM",
	Long:  `Read from the TPM`,
	Args:  cobra.NoArgs,
}

var pcrHashAlgo = tpm2.AlgUnknown

var pcrCmd = &cobra.Command{
	Use:   "pcr",
	Short: "Read PCRs from the TPM",
	Long: `Read PCRs from the TPM

Based on --hash-algo and --pcrs flags, read the contents of the TPM's PCRs.

If --hash-algo is not provided, all banks of PCRs will be read.
If --pcrs is not provided, all PCRs are read for that hash algorithm.`,
	Args: cobra.NoArgs,
	RunE: func(*cobra.Command, []string) error {
		rwc, err := openTpm()
		if err != nil {
			return err
		}
		defer rwc.Close()

		if pcrHashAlgo != tpm2.AlgUnknown {
			sel := tpm2.PCRSelection{Hash: pcrHashAlgo, PCRs: pcrs}
			if len(sel.PCRs) == 0 {
				sel = client.FullPcrSel(sel.Hash)
			}

			fmt.Fprintf(debugOutput(), "Reading %v PCRs (%v)\n", sel.Hash, sel.PCRs)
			pcrs, err := client.ReadPCRs(rwc, sel)
			if err != nil {
				return err
			}
			return internal.FormatPCRs(dataOutput(), pcrs)
		}
		if len(pcrs) != 0 {
			return errors.New("--hash-algo must be used with --pcrs")
		}

		fmt.Fprintln(debugOutput(), "Reading all PCRs")
		banks, err := client.ReadAllPCRs(rwc)
		if err != nil {
			return err
		}

		for _, bank := range banks {
			if err = internal.FormatPCRs(dataOutput(), bank); err != nil {
				return err
			}
		}
		return nil
	},
}

// nvReadAuthHandle returns the handle that authorizes reading the NV index.
// When --auth-handle is "auto", the handle is derived from the index's read
// authorization attributes, matching the TPM's own authorization rules.
func nvReadAuthHandle(rwc io.ReadWriter, index tpmutil.Handle) (tpmutil.Handle, error) {
	switch strings.ToLower(nvAuthHandle) {
	case "owner":
		return tpm2.HandleOwner, nil
	case "platform":
		return tpm2.HandlePlatform, nil
	case "index":
		return index, nil
	case "auto":
	default:
		return 0, fmt.Errorf("unknown --auth-handle %q, want one of auto, owner, platform, index", nvAuthHandle)
	}

	pub, err := tpm2.NVReadPublic(rwc, index)
	if err != nil {
		return 0, fmt.Errorf("reading NV index public area: %w", err)
	}
	switch {
	case pub.Attributes&tpm2.AttrOwnerRead != 0:
		return tpm2.HandleOwner, nil
	case pub.Attributes&tpm2.AttrAuthRead != 0:
		return index, nil
	case pub.Attributes&tpm2.AttrPPRead != 0:
		return tpm2.HandlePlatform, nil
	case pub.Attributes&tpm2.AttrPolicyRead != 0:
		return 0, fmt.Errorf("NV index %#x can only be read with policy authorization, which is unsupported", uint32(index))
	default:
		return 0, fmt.Errorf("NV index %#x has no read authorization attributes set (%v)", uint32(index), pub.Attributes)
	}
}

var nvReadCmd = &cobra.Command{
	Use:   "nvdata",
	Short: "Read TPM NVData",
	Long: `Read NVData at a particular NVIndex

Based on the --index flag, this reads all of the NVData present at that NVIndex.
The read is authenticated with an empty password and, by default, with the
handle implied by the index's read authorization attributes: the owner
hierarchy for OWNERREAD indexes, the index itself for AUTHREAD indexes, or the
platform hierarchy for PPREAD indexes. Use --auth-handle to override this.`,
	Args: cobra.NoArgs,
	RunE: func(*cobra.Command, []string) error {
		rwc, err := openTpm()
		if err != nil {
			return err
		}
		defer rwc.Close()

		index := tpmutil.Handle(nvIndex)
		authHandle, err := nvReadAuthHandle(rwc, index)
		if err != nil {
			return err
		}
		fmt.Fprintf(debugOutput(), "Reading NVData at index %#x authorized by handle %#x\n", nvIndex, uint32(authHandle))

		data, err := tpm2.NVReadEx(rwc, index, authHandle, "", 0)
		if err != nil {
			return err
		}
		if _, err := dataOutput().Write(data); err != nil {
			return fmt.Errorf("cannot output NVData: %w", err)
		}
		return nil
	},
}

func init() {
	RootCmd.AddCommand(readCmd)
	readCmd.AddCommand(pcrCmd)
	readCmd.AddCommand(nvReadCmd)
	addOutputFlag(pcrCmd)
	addPCRsFlag(pcrCmd)
	addHashAlgoFlag(pcrCmd, &pcrHashAlgo)
	addIndexFlag(nvReadCmd)
	nvReadCmd.MarkPersistentFlagRequired("index")
	addNVAuthHandleFlag(nvReadCmd)
	addOutputFlag(nvReadCmd)
}
