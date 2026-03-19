package cmd

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/google/go-tdx-guest/abi"
	tg "github.com/google/go-tdx-guest/client"
	"github.com/google/go-tdx-guest/pcs"
	"github.com/google/go-tdx-guest/verify"
	"github.com/spf13/cobra"
)

var (
	ppidFlag       string
	quoteFileFlag  string
	bucketNameFlag string
	gcsBaseURL     = "https://storage.googleapis.com"
)

func getPPIDFromQuote(quote any) (string, error) {
	chain, err := verify.ExtractChainFromQuote(quote)
	if err != nil {
		return "", fmt.Errorf("could not extract PCK certificate chain from quote: %w", err)
	}
	if chain == nil || chain.PCKCertificate == nil {
		return "", errors.New("PCK certificate is missing in the quote")
	}
	exts, err := pcs.PckCertificateExtensions(chain.PCKCertificate)
	if err != nil {
		return "", fmt.Errorf("could not extract PCK extensions: %w", err)
	}
	if exts.PPID == "" {
		return "", errors.New("PPID is empty in PCK extensions")
	}
	return exts.PPID, nil
}

var provenanceCmd = &cobra.Command{
	Use:   "provenance",
	Short: "Fetch VM provenance reference values from a GCS bucket.",
	Long: `Fetch a JSON file containing machine info/provenance from a public GCS bucket based on a PPID.
The PPID can be provided explicitly, extracted from a TDX quote file, or obtained by fetching a quote from the currently running TDX CVM.`,
	Args: cobra.NoArgs,
	RunE: func(*cobra.Command, []string) error {
		ppid, err := resolvePPID()
		if err != nil {
			return err
		}

		bodyBytes, err := fetchProvenanceData(ppid, bucketNameFlag)
		if err != nil {
			return err
		}

		if _, err := dataOutput().Write(bodyBytes); err != nil {
			return fmt.Errorf("failed to write output: %w", err)
		}

		return nil
	},
}

func resolvePPID() (string, error) {
	if ppidFlag != "" {
		return ppidFlag, nil
	}
	if quoteFileFlag != "" {
		quoteBytes, err := readBytes(quoteFileFlag)
		if err != nil {
			return "", fmt.Errorf("failed to read quote file at %s: %w", quoteFileFlag, err)
		}
		quoteProto, err := abi.QuoteToProto(quoteBytes)
		if err != nil {
			return "", fmt.Errorf("failed to parse quote bytes: %w", err)
		}
		ppid, err := getPPIDFromQuote(quoteProto)
		if err != nil {
			return "", fmt.Errorf("failed to extract PPID from quote file: %w", err)
		}
		return ppid, nil
	}

	qp, err := tg.GetQuoteProvider()
	if err != nil {
		return "", fmt.Errorf("failed to get quote provider: %w", err)
	}
	if err := qp.IsSupported(); err != nil {
		return "", fmt.Errorf("TDX quote provider not supported on this platform: %w", err)
	}

	var tdxNonce [64]byte
	quote, err := tg.GetQuote(qp, tdxNonce)
	if err != nil {
		return "", fmt.Errorf("failed to fetch local TDX quote: %w", err)
	}
	ppid, err := getPPIDFromQuote(quote)
	if err != nil {
		return "", fmt.Errorf("failed to extract PPID from local quote: %w", err)
	}
	return ppid, nil
}

func fetchProvenanceData(ppid string, bucket string) ([]byte, error) {
	fmt.Fprintf(debugOutput(), "Using PPID: %s\n", ppid)
	fmt.Fprintf(debugOutput(), "Using GCS Bucket: %s\n", bucket)

	url := fmt.Sprintf("%s/%s/%s.json", gcsBaseURL, bucket, ppid)
	fmt.Fprintf(debugOutput(), "Fetching from URL: %s\n", url)

	client := &http.Client{
		Timeout: 30 * time.Second,
	}
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch from GCS: %w", err)
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, parseGCSError(resp, bodyBytes, ppid, bucket)
	}

	return bodyBytes, nil
}

func parseGCSError(resp *http.Response, bodyBytes []byte, ppid string, bucket string) error {
	if resp.StatusCode == http.StatusNotFound {
		bodyStr := string(bodyBytes)
		if strings.Contains(bodyStr, "NoSuchBucket") {
			return fmt.Errorf("GCS request failed: bucket '%s' not found (404)", bucket)
		}
		if strings.Contains(bodyStr, "NoSuchKey") {
			return fmt.Errorf("GCS request failed: file '%s.json' not found in bucket '%s' (404)", ppid, bucket)
		}
		return fmt.Errorf("GCS request failed with status: %s (bucket '%s' or file '%s.json' not found)", resp.Status, bucket, ppid)
	}
	return fmt.Errorf("GCS request failed with status: %s", resp.Status)
}

func init() {
	RootCmd.AddCommand(provenanceCmd)
	provenanceCmd.Flags().StringVar(&ppidFlag, "ppid", "", "Direct PPID string to use")
	provenanceCmd.Flags().StringVar(&quoteFileFlag, "quote", "", "Path to a TDX quote file to extract PPID from")
	provenanceCmd.Flags().StringVar(&bucketNameFlag, "bucket", "my-default-bucket", "The public GCS bucket name to fetch the provenance document from")
	addOutputFlag(provenanceCmd)
}
