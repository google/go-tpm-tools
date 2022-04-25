// package main is a program that will start a container with attestation.
package main

import (
	"context"
	// 	"flag"
	"log"

	"google.golang.org/api/idtoken"
	"google.golang.org/api/option"
	// 	"os"
	// 	"cloud.google.com/go/compute/metadata"
	// 	"github.com/containerd/containerd"
	// 	"github.com/containerd/containerd/defaults"
	// 	"github.com/containerd/containerd/namespaces"
	// 	"github.com/google/go-tpm-tools/launcher/spec"
	// 	"github.com/google/go-tpm/tpm2"
)

// var (
// 	useLocalImage = flag.Bool("use_local_image", false, "use local image instead of pulling image from the repo, only for testing purpose")
// 	serverAddr    = flag.String("addr", "", "The server address in the format of host:port")
// )

func tokenTest() {
	ctx := context.Background()

	serviceAccounts := []string{
		"impersonate1@jessieqliu-test.iam.gserviceaccount.com",
		"impersonate2@jessieqliu-test.iam.gserviceaccount.com",
		"impersonate3@jessieqliu-test.iam.gserviceaccount.com",
	}

	fetcher, err := newImpersonatedTokenFetcher(ctx)
	if err != nil {
		log.Fatalf("Creating fetcher failed: %v", err)
		return
	}

	token, err := fetcher.fetchIDTokenFromChain(serviceAccounts, "test_aud")
	if err != nil {
		log.Fatalf("Fetching failed: %v", err)
		return
	}

	log.Println("Fetching succeeded")

	validator, err := idtoken.NewValidator(ctx, option.WithoutAuthentication())
	if err != nil {
		log.Fatalf("Failed to create validator: %v", err)
		return
	}

	payload, err := validator.Validate(ctx, token, "test_aud")
	if err != nil {
		log.Fatalf("Failed to validate token: %v", err)
		return
	}

	email, ok := payload.Claims["email"]
	if !ok {
		log.Fatal("Token has no email claim.")
		return
	}

	log.Printf("Token contains email: %v", email)
}

func main() {
	tokenTest()
	// flag.Parse()
	// log.SetOutput(os.Stdout)
	// log.Println("TEE container launcher starting...")
	// defer log.Println("TEE container launcher exited successfully")

	// mdsClient := metadata.NewClient(nil)
	// spec, err := spec.GetLauncherSpec(mdsClient)
	// if err != nil {
	// 	log.Fatal(err)
	// }

	// spec.UseLocalImage = *useLocalImage
	// spec.AttestationServiceAddr = *serverAddr
	// log.Println("Launcher Spec: ", spec)

	// client, err := containerd.New(defaults.DefaultAddress)
	// if err != nil {
	// 	log.Fatal(err)
	// }
	// defer client.Close()

	// ctx := namespaces.WithNamespace(context.Background(), namespaces.Default)
	// tpm, err := tpm2.OpenTPM("/dev/tpmrm0")
	// if err != nil {
	// 	log.Fatal(err)
	// 	return
	// }
	// defer tpm.Close()

	// token, err := RetrieveAuthToken(mdsClient)
	// if err != nil {
	// 	log.Printf("Failed to retrieve auth token: %v, using empty auth", err)
	// }

	// r, err := NewRunner(ctx, client, token, spec, mdsClient, tpm)
	// if err != nil {
	// 	log.Fatal(err)
	// }
	// defer r.Close(ctx)

	// err = r.Run(ctx)
	// if err != nil {
	// 	log.Fatal(err)
	// }
}
