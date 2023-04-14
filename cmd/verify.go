package cmd


import (
   "crypto"
   "fmt"
   "io"


   pb "github.com/google/go-tpm-tools/proto/attest"
   "github.com/google/go-tpm-tools/server"
   "github.com/google/go-tpm/tpm2"
   "github.com/spf13/cobra"
   "google.golang.org/protobuf/proto"
)


var verifyCmd = &cobra.Command{
   Use:   "verify",
   Short: "Output attestation related data",
   Args:  cobra.NoArgs,
}
var debugCmd = &cobra.Command{
   Use:   "debug",
   Short: "VerifyAttestation and Output attestation related data",
   RunE: func(cmd *cobra.Command, args []string) error {
       attestationBytes, err := io.ReadAll(dataInput())
       if err != nil {
           return err
       }
       attestation := &pb.Attestation{}


       if format == "binarypb" {
           err = proto.Unmarshal(attestationBytes, attestation)
       } else if format == "textproto" {
           err = unmarshalOptions.Unmarshal(attestationBytes, attestation)
       } else {
           return fmt.Errorf("format should be either binarypb or textproto")
       }
       if err != nil {
           return fmt.Errorf("fail to unmarshal attestation report: %v", err)
       }


       pub, err := tpm2.DecodePublic(attestation.GetAkPub())


       if err != nil {
           return err
       }
       cryptoPub, err := pub.Key()
       if err != nil {
           return err
       }
       ms, err := server.VerifyAttestation(attestation, server.VerifyOpts{Nonce: nonce, TrustedAKs: []crypto.PublicKey{cryptoPub}})
       if err != nil {
           return fmt.Errorf("verifying attestation: %w", err)
       }
       out, err := marshalOptions.Marshal(ms)
       if err != nil {
           return nil
       }
       if _, err := dataOutput().Write(out); err != nil {
           return fmt.Errorf("failed to write verified attestation report: %v", err)
       }
       return nil
   },
}


func init() {
   RootCmd.AddCommand(verifyCmd)
   verifyCmd.AddCommand(debugCmd)
   addNonceFlag(debugCmd)
   addOutputFlag(debugCmd)
   addInputFlag(debugCmd)
   addFormatFlag(debugCmd)
}

