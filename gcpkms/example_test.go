package gcpkms_test

import (
	"context"
	"log"

	"github.com/dcadolph/cipher"
	"github.com/dcadolph/cipher/gcpkms"
)

// ExampleNewProvider builds a Provider from one or more GCP KMS
// resource ids using application default credentials.
func ExampleNewProvider() {
	kp, err := gcpkms.NewProvider(
		"projects/my-project/locations/us/keyRings/cipher/cryptoKeys/prod",
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
