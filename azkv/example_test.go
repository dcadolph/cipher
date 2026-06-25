package azkv_test

import (
	"context"
	"log"

	"github.com/dcadolph/cipher"
	"github.com/dcadolph/cipher/azkv"
)

// ExampleNewProvider builds a Provider that uses an Azure Key Vault
// key for sops wrap. Credentials come from the azure default
// credential chain (environment, managed identity, az cli).
func ExampleNewProvider() {
	kp, err := azkv.NewProvider(
		"https://my-vault.vault.azure.net/keys/cipher/00112233445566778899aabbccddeeff",
	)
	if err != nil {
		log.Fatal(err)
	}
	enc := cipher.NewEncoder(kp)
	_, err = enc.Encode(context.Background(), "secrets.yaml", []byte("foo: bar\n"))
	if err != nil {
		log.Fatal(err)
	}
}
