// package main is a program that will start a container with attestation.
package main

import (
	"context"
	"flag"
	"log"
	"os"

	"cloud.google.com/go/compute/metadata"
	"github.com/containerd/containerd"
	"github.com/containerd/containerd/defaults"
	"github.com/containerd/containerd/namespaces"
	"github.com/google/go-tpm-tools/launcher/spec"
	"github.com/google/go-tpm/tpm2"
)

var (
	useLocalImage = flag.Bool("use_local_image", false, "use local image instead of pulling image from the repo, only for testing purpose")
	serverAddr    = flag.String("addr", "", "The server address in the format of host:port")
)

func main() {
	flag.Parse()
	log.SetOutput(os.Stdout)
	log.Println("TEE container launcher starting...")
	defer log.Println("TEE container launcher exited successfully")

	mdsClient := metadata.NewClient(nil)
	spec, err := spec.GetLauncherSpec(mdsClient)
	if err != nil {
		log.Fatal(err)
	}

	spec.UseLocalImage = *useLocalImage
	spec.AttestationServiceAddr = *serverAddr
	log.Println("Launcher Spec: ", spec)

	client, err := containerd.New(defaults.DefaultAddress)
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	ctx := namespaces.WithNamespace(context.Background(), namespaces.Default)
	tpm, err := tpm2.OpenTPM("/dev/tpmrm0")
	if err != nil {
		log.Fatal(err)
		return
	}
	defer tpm.Close()

	token, err := RetriveAuthToken(mdsClient)
	if err != nil {
		log.Printf("Failed to retrive auth token: %v, using empty auth", err)
	}

	r, err := NewRunner(ctx, client, token, spec, mdsClient, tpm)
	if err != nil {
		log.Fatal(err)
	}
	defer r.Close(ctx)

	err = r.Run(ctx)
	if err != nil {
		log.Fatal(err)
	}
}
