package main

import (
	"ca-generator/certificates"
	"ca-generator/encoder"
	"fmt"
	"log"
)

func main() {

	artifacts, err := certificates.GenerateCA()

	if err != nil {
		log.Fatal(err)
	}

	fmt.Println()

	fmt.Printf(
		"ROOT_PRIVATE_KEY_BASE64=%s\n\n",
		encoder.EncodeBase64(
			artifacts.PrivateKey,
		),
	)

	fmt.Printf(
		"ROOT_PUBLIC_KEY_BASE64=%s\n\n",
		encoder.EncodeBase64(
			artifacts.PublicKey,
		),
	)

	fmt.Printf(
		"ROOT_CERTIFICATE_BASE64=%s\n\n",
		encoder.EncodeBase64(
			artifacts.Certificate,
		),
	)
}
