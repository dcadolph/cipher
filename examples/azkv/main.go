// Package main demonstrates the Azure Key Vault backend. Encrypts a
// small YAML using one or more Key Vault key URLs taken from the
// AZURE_KV_URLS env var. Authentication uses the default Azure
// credential chain (env, managed identity, az CLI).
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/dcadolph/cipher"
	"github.com/dcadolph/cipher/azkv"
)

func main() {
	ctx := context.Background()

	if strings.TrimSpace(os.Getenv("AZURE_KV_URLS")) == "" {
		log.Fatal("set AZURE_KV_URLS to a comma-separated list of Key Vault key URLs " +
			"(https://VAULT.vault.azure.net/keys/KEY/VERSION)")
	}
	urls := strings.Split(os.Getenv("AZURE_KV_URLS"), ",")

	provider, err := azkv.NewProvider(urls...)
	if err != nil {
		log.Fatalf("azkv provider: %v", err)
	}
	enc := cipher.NewEncoder(provider)
	dec := cipher.NewDecoder()

	plain := []byte("api_key: azure-kv-secret\n")
	ciphertext, err := enc.Encode(ctx, "secrets.yaml", plain)
	if err != nil {
		log.Fatalf("encode: %v", err)
	}
	fmt.Printf("encrypted via %d Azure Key Vault key(s), %d ciphertext bytes\n",
		len(urls), len(ciphertext))

	roundTrip, err := dec.Decode(ctx, "secrets.yaml", ciphertext)
	if err != nil {
		log.Fatalf("decode: %v", err)
	}
	fmt.Printf("decoded plaintext:\n%s", roundTrip)
}
