package decrypt

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/dcadolph/cipher/file"
)

// SopsPrivateKeyENV is used to set environment variable for the SOPS age private key.
const SopsPrivateKeyENV = "SOPS_AGE_KEY"

// DecryptWalkSopsAge returns a filepath.WalkFunc that decrypts file content.
//
// Given file.SkipFunc dictate which files should not be decrypted.
//
// Constructor panics if age private key is empty or if it fails to set the key's value as an
// environment variable. For the latter, the key's value is not echoed.
func DecryptWalkSopsAge(agePrivateKey string, sf ...file.SkipFunc) filepath.WalkFunc {

	if agePrivateKey == "" {
		panic("decrypt walk sops age: private key required")
	}

	if setErr := os.Setenv(SopsPrivateKeyENV, agePrivateKey); setErr != nil {
		panic("decrypt walk sops age: setting private key in environment failed")
	}

	wf := func(path string, info os.FileInfo, walkErr error) error {

		if info.IsDir() {
			return nil
		}

		for _, skipFunc := range sf {

			skipFile, skipFileErr := skipFunc(path)
			if skipFileErr != nil {
				return &Error{
					Cause:     fmt.Errorf("%w: check if file should be skipped failed", ErrDecrypt),
					RootCause: skipFileErr,
				}
			}

			if skipFile {
				return nil
			}
		}

		fileData, readErr := os.ReadFile(path)
		if readErr != nil {
			return &Error{
				Cause:     fmt.Errorf("reading file %s: %w", path, ErrDecrypt),
				RootCause: readErr,
			}
		}

		data, decodeErr := sopsDecode(path, fileData)
		if decodeErr != nil {
			return decodeErr
		}

		fileInfo, statErr := os.Stat(path)
		if statErr != nil {
			return &Error{
				Cause:     fmt.Errorf("getting file info from %s: %w", path, ErrDecrypt),
				RootCause: statErr,
			}
		}

		if writeErr := os.WriteFile(path, data, fileInfo.Mode().Perm()); writeErr != nil {
			return &Error{
				Cause:     fmt.Errorf("writing decrypted file %s: %w", path, ErrDecrypt),
				RootCause: writeErr,
			}
		}

		return nil
	}

	return wf
}
