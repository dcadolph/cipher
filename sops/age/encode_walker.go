package age

import (
	"path/filepath"
	"regexp"

	"github.com/dcadolph/cipher/file"
	"github.com/dcadolph/cipher/sops"
)

// EncodeWalker returns a sops.EncodeWalker that uses the given age public key for encryption.
//
// Regex is the encryption regex, which dictates what parts of a file should be encrypted.
//
// Age public key is used to generate the key groups required for encryption.
//
// For more, see sops.EncodeWalker.
//
// Constructor panics if regex is nil or if age public key is empty.
func EncodeWalker(regex *regexp.Regexp, agePublicKey string, sf ...file.SkipFunc) (filepath.WalkFunc, error) {

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

	return sops.EncodeWalker(regex, kg, sf...), nil
}
