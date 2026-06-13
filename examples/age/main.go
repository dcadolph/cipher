// Package main demonstrates the age backend end to end: generate a
// fresh identity, encrypt a YAML payload to the recipient, then
// decrypt it again using the matching secret.
package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/dcadolph/cipher"
	"github.com/dcadolph/cipher/age"
)

func main() {
	ctx := context.Background()

	id, err := age.GenerateIdentity()
	if err != nil {
		log.Fatalf("generate age identity: %v", err)
	}
	fmt.Println("recipient (safe to share):", id.Recipient)
	// DEMO ONLY. The secret is printed to stderr so a normal stdout
	// redirect cannot accidentally capture it. In a real program,
	// write the secret directly to a 0600 file or a secret manager
	// without ever crossing the terminal.
	fmt.Fprintln(os.Stderr, "secret    (DEMO ONLY, do not log):", id.Secret)

	provider, err := age.NewProvider(id.Recipient)
	if err != nil {
		log.Fatalf("age provider: %v", err)
	}
	enc := cipher.NewEncoder(provider)

	plain := []byte("api_key: super-secret-value\n")
	encrypted, err := enc.Encode(ctx, "secrets.yaml", plain)
	if err != nil {
		log.Fatalf("encode: %v", err)
	}
	fmt.Printf("\nciphertext (%d bytes):\n%s\n", len(encrypted), encrypted)

	if err := os.Setenv("SOPS_AGE_KEY", id.Secret); err != nil {
		log.Fatalf("set SOPS_AGE_KEY: %v", err)
	}
	dec := cipher.NewDecoder()
	roundTrip, err := dec.Decode(ctx, "secrets.yaml", encrypted)
	if err != nil {
		log.Fatalf("decode: %v", err)
	}
	fmt.Printf("\nroundtrip plaintext:\n%s\n", roundTrip)
}
