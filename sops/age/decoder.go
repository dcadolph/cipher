package age

import (
	"os"

	"github.com/dcadolph/cipher/decode"
	"github.com/dcadolph/cipher/sops"
)

// SopsPrivateKeyENV is used to set environment variable for the SOPS age private key.
const SopsPrivateKeyENV = "SOPS_AGE_KEY"

// Decoder returns a SOPS decode.Decoder for decrypting age-encrypted files.
func Decoder(agePrivateKey string) decode.Decoder {

	if agePrivateKey == "" {
		panic("decoder: age private key required")
	}

	if setErr := os.Setenv(SopsPrivateKeyENV, agePrivateKey); setErr != nil {
		panic("decrypt walk sops age: setting private key in environment failed")
	}

	return sops.Decoder()
}
