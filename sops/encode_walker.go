package sops

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"

	"github.com/dcadolph/cipher/file"
	"go.mozilla.org/sops/v3"
	"go.mozilla.org/sops/v3/aes"
)

// EncodeWalker returns a filepath.WalkFunc that encrypts files on disk using SOPS encryption.
//
// Regex is the encryption regex, which dictates what parts of a file should be encrypted.
//
// sops.KeyGroup dictate what type of encryption should be performed (e.g. age encryption if
// sops.KeyGroup is slice of age.MasterKey).
//
// file.SkipFunc dictate which files should not be encrypted (which files to file). If none are
// provided, EncryptWalk will attempt to encrypt all files on the file system.
//
// File input format and output format is based on a given file's extension. For more, see
// formats.FormatForPath.
//
// If a file has a YAML extension, but contains a JSON object, the result will be written as
// a YAML object. If a file has a JSON extension, but contains YAML, ErrEncode will be returned.
//
// Constructor panics if regex is nil or if key groups is empty.
func EncodeWalker(regex *regexp.Regexp, keyGroups []sops.KeyGroup, sf ...file.SkipFunc) filepath.WalkFunc {

	if regex == nil {
		panic("encrypt walk: regex required")
	}

	if len(keyGroups) == 0 {
		panic("encrypt walk: key groups required")
	}

	e := &encoder{
		cipher:    aes.NewCipher(),
		regex:     regex,
		keyGroups: keyGroups,
	}

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
				Cause:     fmt.Errorf("getting file info from %s: %w", path, ErrEncode),
				RootCause: statErr,
			}
		}

		encryptedData, emitErr := e.encryptedBytes(path)
		if emitErr != nil {
			return &Error{
				Cause:     fmt.Errorf("encrypting file %s: %w", path, ErrEncode),
				RootCause: emitErr,
			}
		}

		if writeErr := os.WriteFile(path, encryptedData, fileInfo.Mode().Perm()); writeErr != nil {
			return &Error{
				Cause:     fmt.Errorf("writing encrypted file to %s: %w", path, ErrEncode),
				RootCause: writeErr,
			}
		}

		return nil
	}

	return wf
}
