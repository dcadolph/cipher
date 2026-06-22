// Package main demonstrates recipient management without re-encrypting
// the payload. Encrypts to Alice, adds Bob, verifies both can decrypt,
// then removes Alice and verifies only Bob can.
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

	alice, err := age.GenerateIdentity()
	if err != nil {
		log.Fatalf("alice: %v", err)
	}
	bob, err := age.GenerateIdentity()
	if err != nil {
		log.Fatalf("bob: %v", err)
	}
	fmt.Printf("alice: %s\nbob:   %s\n\n", alice.Recipient, bob.Recipient)

	aliceProvider, err := age.NewProvider(alice.Recipient)
	if err != nil {
		log.Fatalf("alice provider: %v", err)
	}
	enc := cipher.NewEncoder(aliceProvider)

	plain := []byte("payload: stays-the-same\n")
	ciphertext, err := enc.Encode(ctx, "secrets.yaml", plain)
	if err != nil {
		log.Fatalf("encode: %v", err)
	}
	fmt.Printf("encrypted to alice (%d bytes)\n", len(ciphertext))

	bobProvider, err := age.NewProvider(bob.Recipient)
	if err != nil {
		log.Fatalf("bob provider: %v", err)
	}
	if err := os.Setenv("SOPS_AGE_KEY", alice.Secret); err != nil {
		log.Fatalf("set SOPS_AGE_KEY: %v", err)
	}
	withBob, err := cipher.AddRecipient(
		ctx, "secrets.yaml", ciphertext, bobProvider, cipher.DecoderOptions{},
	)
	if err != nil {
		log.Fatalf("add bob: %v", err)
	}
	fmt.Printf("added bob (%d bytes)\n", len(withBob))

	tryDecode("alice", alice.Secret, withBob)
	tryDecode("bob", bob.Secret, withBob)

	withoutAlice, err := cipher.RemoveRecipient("secrets.yaml", withBob, alice.Recipient)
	if err != nil {
		log.Fatalf("remove alice: %v", err)
	}
	fmt.Printf("\nremoved alice (%d bytes)\n", len(withoutAlice))

	tryDecode("alice", alice.Secret, withoutAlice)
	tryDecode("bob", bob.Secret, withoutAlice)
}

// tryDecode sets SOPS_AGE_KEY to secret and tries to decode data,
// printing success or the failure reason. Used to demonstrate which
// recipient identities can still unwrap the data key.
func tryDecode(label, secret string, data []byte) {
	if err := os.Setenv("SOPS_AGE_KEY", secret); err != nil {
		log.Fatalf("set SOPS_AGE_KEY: %v", err)
	}
	dec := cipher.NewDecoder()
	out, err := dec.Decode(context.Background(), "secrets.yaml", data)
	if err != nil {
		fmt.Printf("  %-5s decode: FAIL (%v)\n", label, err)
		return
	}
	fmt.Printf("  %-5s decode: OK  (%d bytes plaintext)\n", label, len(out))
}
