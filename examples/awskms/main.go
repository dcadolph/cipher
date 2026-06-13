// Package main demonstrates the AWS KMS backend. Encrypts a small YAML
// payload using one or more KMS key ARNs taken from the AWS_KMS_ARNS
// env var. AWS credentials come from the default SDK chain
// (environment, shared credentials file, IAM role, IRSA).
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/dcadolph/cipher"
	"github.com/dcadolph/cipher/kms"
)

func main() {
	ctx := context.Background()

	if strings.TrimSpace(os.Getenv("AWS_KMS_ARNS")) == "" {
		log.Fatal("set AWS_KMS_ARNS to a comma-separated list of AWS KMS key ARNs")
	}
	arns := strings.Split(os.Getenv("AWS_KMS_ARNS"), ",")

	provider, err := kms.NewProvider(kms.ProviderOptions{
		Profile: os.Getenv("AWS_PROFILE"),
		EncryptionContext: map[string]string{
			"app":         "cipher-example",
			"environment": "demo",
		},
	}, arns...)
	if err != nil {
		log.Fatalf("kms provider: %v", err)
	}
	enc := cipher.NewEncoder(provider)
	dec := cipher.NewDecoder()

	plain := []byte("api_key: aws-kms-secret\n")
	ciphertext, err := enc.Encode(ctx, "secrets.yaml", plain)
	if err != nil {
		log.Fatalf("encode: %v", err)
	}
	fmt.Printf("encrypted with %d KMS key(s), %d ciphertext bytes\n", len(arns), len(ciphertext))

	roundTrip, err := dec.Decode(ctx, "secrets.yaml", ciphertext)
	if err != nil {
		log.Fatalf("decode: %v", err)
	}
	fmt.Printf("decoded plaintext:\n%s", roundTrip)
}
