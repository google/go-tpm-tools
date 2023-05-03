// package main is a binary that will print out the MDS vars and check the token.
package main

import (
	"fmt"
	"os"

	"github.com/golang-jwt/jwt/v4"
)

const tokendir = "/run/container_launcher/attestation_verifier_claims_token"

func main() {
	fmt.Println("Workload running")
	fmt.Println("Workload args:", os.Args)
	fmt.Println("Workload env vars:")
	for _, e := range os.Environ() {
		fmt.Println(e)
	}

	filedata, err := os.ReadFile(tokendir)
	if err != nil {
		fmt.Println(err)
		return
	}

	token, _, err := new(jwt.Parser).ParseUnverified(string(filedata), jwt.MapClaims{})
	if err != nil {
		fmt.Println(err)
		return
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		fmt.Println(err)
		return
	}
	fmt.Println("aud: ", claims["aud"])
	fmt.Println("iss: ", claims["iss"])
	fmt.Println("secboot: ", claims["secboot"])
	fmt.Println("oemid: ", claims["oemid"])
	fmt.Println("hwmodel: ", claims["hwmodel"])
	fmt.Println("swname: ", claims["swname"])

	fmt.Println("Token looks okay")
}
