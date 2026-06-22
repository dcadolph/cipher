// Package main demonstrates the PGP backend. Encrypts a small YAML to
// one or more GPG fingerprints taken from the PGP_FINGERPRINTS env
// var. The local gpg binary on PATH does both wrap and unwrap.
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/dcadolph/cipher"
	"github.com/dcadolph/cipher/pgp"
)

func main() {
	ctx := context.Background()

	if strings.TrimSpace(os.Getenv("PGP_FINGERPRINTS")) == "" {
		log.Fatal("set PGP_FINGERPRINTS to a comma-separated list of GPG key fingerprints")
	}
	fingerprints := strings.Split(os.Getenv("PGP_FINGERPRINTS"), ",")

	provider, err := pgp.NewProvider(fingerprints...)
	if err != nil {
		log.Fatalf("pgp provider: %v", err)
	}
	enc := cipher.NewEncoder(provider)
	dec := cipher.NewDecoder()

	plain := []byte("api_key: pgp-secret\n")
	ciphertext, err := enc.Encode(ctx, "secrets.yaml", plain)
	if err != nil {
		log.Fatalf("encode: %v", err)
	}
	fmt.Printf("encrypted to %d PGP fingerprint(s), %d ciphertext bytes\n",
		len(fingerprints), len(ciphertext))

	roundTrip, err := dec.Decode(ctx, "secrets.yaml", ciphertext)
	if err != nil {
		log.Fatalf("decode: %v", err)
	}
	fmt.Printf("decoded plaintext:\n%s", roundTrip)
}
