package age

import (
	"regexp"

	"github.com/dcadolph/cipher/encode"
	"github.com/dcadolph/cipher/sops"
)

// Encoder returns a encode.Encoder (using sops.Encoder) that uses the given age public key for
// encryption.
//
// Regex is the encryption regex, which dictates what parts of a file should be encrypted.
//
// Age public key is used to generate the key groups required for encryption.
//
// For more, see sops.Encoder.
//
// Constructor panics if regex is nil or if age public key is empty.
func Encoder(regex *regexp.Regexp, agePublicKey string) (encode.Encoder, error) {

	if regex == nil {
		panic("encoder: regex required")
	}

	if agePublicKey == "" {
		panic("encoder: age public key required")
	}

	kg, err := KeyGroups(agePublicKey)
	if err != nil {
		return nil, err
	}

	return sops.Encoder(regex, kg), nil
}
