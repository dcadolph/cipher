// Package main demonstrates Rotate: re-encrypt a file with a fresh
// data key while keeping the same plaintext and recipients. The
// ciphertext changes byte-for-byte even though the file content does
// not.
package main

import (
	"bytes"
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
	if err := os.Setenv("SOPS_AGE_KEY", id.Secret); err != nil {
		log.Fatalf("set SOPS_AGE_KEY: %v", err)
	}

	provider, err := age.NewProvider(id.Recipient)
	if err != nil {
		log.Fatalf("age provider: %v", err)
	}
	enc := cipher.NewEncoder(provider)
	dec := cipher.NewDecoder()

	plain := []byte("api_key: rotate-me\n")
	original, err := enc.Encode(ctx, "secrets.yaml", plain)
	if err != nil {
		log.Fatalf("encode: %v", err)
	}

	rotated, err := cipher.Rotate(ctx, "secrets.yaml", original, enc, dec)
	if err != nil {
		log.Fatalf("rotate: %v", err)
	}

	fmt.Printf("original  ciphertext: %d bytes\n", len(original))
	fmt.Printf("rotated   ciphertext: %d bytes\n", len(rotated))
	fmt.Printf("byte equal:           %v\n", bytes.Equal(original, rotated))

	roundTrip, err := dec.Decode(ctx, "secrets.yaml", rotated)
	if err != nil {
		log.Fatalf("decode rotated: %v", err)
	}
	fmt.Printf("plaintext after rotate matches: %v\n", bytes.Equal(plain, roundTrip))
}
