package age

import (
	"path/filepath"
	"regexp"

	"github.com/dcadolph/cipher/file"
	"github.com/dcadolph/cipher/sops"
)

// EncodeWalker returns a filepath.WalkFunc that uses the given age public key to encrypt data using
// SOPS age.
//
// Regex is the encryption regex, which dictates what parts of a file should be encrypted.
//
// Age public key is used to generate the key groups required for encryption.
//
// file.SkipFunc dictate which files should not be encrypted (which files to file). If none are
// provided, EncryptWalk will attempt to encrypt all files on the file system.
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
