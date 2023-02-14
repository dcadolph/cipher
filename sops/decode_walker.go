package sops

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/dcadolph/cipher/file"
)

// DecodeWalker returns a filepath.WalkFunc that decrypts files on disk using SOPS decryption.
//
// file.SkipFunc dictate which files should not be decoded (remain encrypted if encrypted).
func DecodeWalker(sf ...file.SkipFunc) filepath.WalkFunc {

	decoder := Decoder()

	wf := func(path string, info os.FileInfo, walkErr error) error {

		if info.IsDir() {
			return nil
		}

		for _, skipFunc := range sf {

			skipFile, skipFileErr := skipFunc(path)
			if skipFileErr != nil {
				return &Error{
					Cause: fmt.Errorf(
						"%w: check if file should be skipped failed",
						ErrEncode,
					),
					RootCause: skipFileErr,
				}
			}

			if skipFile {
				return nil
			}
		}

		fileInfo, statErr := os.Stat(path)
		if statErr != nil {
			return &Error{
				Cause:     fmt.Errorf("getting file info from %s: %w", path, ErrDecode),
				RootCause: statErr,
			}
		}

		decodedBytes, decodeErr := decoder.Decode(path)
		if decodeErr != nil {
			return &Error{
				Cause:     fmt.Errorf("decoding file %s: %w", path, ErrDecode),
				RootCause: decodeErr,
			}
		}

		if writeErr := os.WriteFile(path, decodedBytes, fileInfo.Mode().Perm()); writeErr != nil {
			return &Error{
				Cause:     fmt.Errorf("writing encrypted file to %s: %w", path, ErrDecode),
				RootCause: writeErr,
			}
		}

		return nil
	}

	return wf
}
