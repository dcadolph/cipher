package vault_test

import (
	"context"
	"log"

	"github.com/dcadolph/cipher"
	"github.com/dcadolph/cipher/vault"
)

// ExampleNewProvider builds a Provider that talks to a vault transit
// key. Vault address and token come from VAULT_ADDR and VAULT_TOKEN.
func ExampleNewProvider() {
	kp, err := vault.NewProvider("https://vault.example.com/v1/transit/keys/cipher")
	if err != nil {
		log.Fatal(err)
	}
	enc := cipher.NewEncoder(kp)
	_, err = enc.Encode(context.Background(), "secrets.yaml", []byte("foo: bar\n"))
	if err != nil {
		log.Fatal(err)
	}
}
