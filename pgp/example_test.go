package pgp_test

import (
	"context"
	"log"

	"github.com/dcadolph/cipher"
	"github.com/dcadolph/cipher/pgp"
)

// ExampleNewProvider builds a Provider from one or more gpg key
// fingerprints. The local gpg binary must hold the matching public
// keys in its keyring at encrypt time, and the private keys at
// decrypt time.
func ExampleNewProvider() {
	kp, err := pgp.NewProvider("AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555")
	if err != nil {
		log.Fatal(err)
	}
	enc := cipher.NewEncoder(kp)
	_, err = enc.Encode(context.Background(), "secrets.yaml", []byte("foo: bar\n"))
	if err != nil {
		log.Fatal(err)
	}
}
