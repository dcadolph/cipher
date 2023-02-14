package age

import (
	"os"
	"path/filepath"

	"github.com/dcadolph/cipher/file"
	"github.com/dcadolph/cipher/sops"
)

// DecodeWalker returns a filepath.WalkFunc for decrypting age-encrypted files.
//
// file.SkipFunc dictate which files should not be decoded (remain encrypted if encrypted).
//
// For more, see sops.DecodeWalker.
//
// Call panics if age private key is empty.
func DecodeWalker(agePrivateKey string, sf ...file.SkipFunc) filepath.WalkFunc {

	if agePrivateKey == "" {
		panic("decoder: age private key required")
	}

	if setErr := os.Setenv(SopsPrivateKeyENV, agePrivateKey); setErr != nil {
		panic("decrypt walk sops age: setting private key in environment failed")
	}

	return sops.DecodeWalker(sf...)
}
