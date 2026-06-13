// Package main demonstrates the GCP KMS backend. Encrypts a small
// YAML using one or more KMS resource IDs taken from the GCP_KMS_IDS
// env var. Credentials come from Google application-default
// credentials (gcloud auth, GOOGLE_APPLICATION_CREDENTIALS, Workload
// Identity).
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/dcadolph/cipher"
	"github.com/dcadolph/cipher/gcpkms"
)

func main() {
	ctx := context.Background()

	if strings.TrimSpace(os.Getenv("GCP_KMS_IDS")) == "" {
		log.Fatal("set GCP_KMS_IDS to a comma-separated list of GCP KMS resource IDs " +
			"(projects/PROJ/locations/LOC/keyRings/RING/cryptoKeys/KEY)")
	}
	ids := strings.Split(os.Getenv("GCP_KMS_IDS"), ",")

	provider, err := gcpkms.NewProvider(ids...)
	if err != nil {
		log.Fatalf("gcpkms provider: %v", err)
	}
	enc := cipher.NewEncoder(provider)
	dec := cipher.NewDecoder()

	plain := []byte("api_key: gcp-kms-secret\n")
	ciphertext, err := enc.Encode(ctx, "secrets.yaml", plain)
	if err != nil {
		log.Fatalf("encode: %v", err)
	}
	fmt.Printf("encrypted with %d GCP KMS key(s), %d ciphertext bytes\n", len(ids), len(ciphertext))

	roundTrip, err := dec.Decode(ctx, "secrets.yaml", ciphertext)
	if err != nil {
		log.Fatalf("decode: %v", err)
	}
	fmt.Printf("decoded plaintext:\n%s", roundTrip)
}
