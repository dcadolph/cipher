// Package main demonstrates provider composition. Three age identities
// are combined three different ways:
//
//   - MergeProviders flattens all keys into a single group. Any one
//     identity can decrypt.
//   - ChainKeyProviders keeps each identity as its own group. The
//     default behavior is still any-group-decrypts.
//   - NewShamirRule with threshold 2 requires at least two of the
//     three groups to recover the data key.
//
// All three are run on the same plaintext to make the difference visible.
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

	ids := []*age.Identity{
		mustIdentity("alice"),
		mustIdentity("bob"),
		mustIdentity("carol"),
	}
	providers := make([]cipher.KeyProvider, len(ids))
	for i, id := range ids {
		p, err := age.NewProvider(id.Recipient)
		if err != nil {
			log.Fatalf("provider %d: %v", i, err)
		}
		providers[i] = p
	}

	plain := []byte("payload: composed-providers\n")

	merged := cipher.NewEncoder(cipher.MergeProviders(providers...))
	mergedCT, err := merged.Encode(ctx, "secrets.yaml", plain)
	if err != nil {
		log.Fatalf("merged encode: %v", err)
	}
	fmt.Printf("merged ciphertext: %d bytes (single key group, any identity decrypts)\n", len(mergedCT))

	chained := cipher.NewEncoder(cipher.ChainKeyProviders(providers...))
	chainedCT, err := chained.Encode(ctx, "secrets.yaml", plain)
	if err != nil {
		log.Fatalf("chained encode: %v", err)
	}
	fmt.Printf("chained ciphertext: %d bytes (three key groups, any group decrypts)\n", len(chainedCT))

	shamirRule := cipher.NewShamirRule(cipher.MatchAll(), 2, providers...)
	shamir := cipher.NewEncoderWith(shamirRule.Provider, shamirRule.Options)
	shamirCT, err := shamir.Encode(ctx, "secrets.yaml", plain)
	if err != nil {
		log.Fatalf("shamir encode: %v", err)
	}
	fmt.Printf("shamir ciphertext:  %d bytes (three groups, threshold 2)\n", len(shamirCT))

	if err := os.Setenv("SOPS_AGE_KEY", ids[0].Secret+"\n"+ids[1].Secret); err != nil {
		log.Fatalf("set SOPS_AGE_KEY: %v", err)
	}
	dec := cipher.NewDecoder()
	plain2, err := dec.Decode(ctx, "secrets.yaml", shamirCT)
	if err != nil {
		log.Fatalf("shamir decode: %v", err)
	}
	fmt.Printf("\nshamir decoded with alice+bob: %s", plain2)
}

// mustIdentity generates a fresh age identity or panics. label is
// printed alongside the recipient so output ties identities to roles.
func mustIdentity(label string) *age.Identity {
	id, err := age.GenerateIdentity()
	if err != nil {
		panic(err)
	}
	fmt.Printf("%-6s recipient: %s\n", label+":", id.Recipient)
	return id
}
