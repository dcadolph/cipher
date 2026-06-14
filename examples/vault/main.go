// Package main demonstrates the HashiCorp Vault Transit backend.
// Encrypts a small YAML using one or more Transit URIs taken from the
// VAULT_TRANSIT_URIS env var. Vault auth comes from VAULT_TOKEN +
// VAULT_ADDR (or ~/.vault-token).
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/dcadolph/cipher"
	"github.com/dcadolph/cipher/vault"
)

func main() {
	ctx := context.Background()

	if strings.TrimSpace(os.Getenv("VAULT_TRANSIT_URIS")) == "" {
		log.Fatal("set VAULT_TRANSIT_URIS to a comma-separated list of Transit URIs " +
			"(https://VAULT/v1/transit/keys/KEY)")
	}
	uris := strings.Split(os.Getenv("VAULT_TRANSIT_URIS"), ",")

	provider, err := vault.NewProvider(uris...)
	if err != nil {
		log.Fatalf("vault provider: %v", err)
	}
	enc := cipher.NewEncoder(provider)
	dec := cipher.NewDecoder()

	plain := []byte("api_key: vault-transit-secret\n")
	ciphertext, err := enc.Encode(ctx, "secrets.yaml", plain)
	if err != nil {
		log.Fatalf("encode: %v", err)
	}
	fmt.Printf("encrypted via %d Vault Transit key(s), %d ciphertext bytes\n", len(uris), len(ciphertext))

	roundTrip, err := dec.Decode(ctx, "secrets.yaml", ciphertext)
	if err != nil {
		log.Fatalf("decode: %v", err)
	}
	fmt.Printf("decoded plaintext:\n%s", roundTrip)
}
