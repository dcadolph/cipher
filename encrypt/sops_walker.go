package encrypt

import (
	"fmt"
	"github.com/dcadolph/cipher/file"
	"go.mozilla.org/sops/v3"
	"go.mozilla.org/sops/v3/aes"
	"os"
	"path/filepath"
	"regexp"
)

// SopsWalker returns a filepath.WalkFunc that encrypts files on disk using SOPS encryption.
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
// a YAML object. If a file has a JSON extension, but contains YAML, ErrEncrypt will be returned.
//
// Constructor panics if regex is nil or if key groups is empty.
func SopsWalker(regex *regexp.Regexp, keyGroups []sops.KeyGroup, sf ...file.SkipFunc) filepath.WalkFunc {

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
					Cause:     fmt.Errorf("%w: check if file should be skipped failed", ErrEncrypt),
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
				Cause:     fmt.Errorf("getting file info from %s: %w", path, ErrEncrypt),
				RootCause: statErr,
			}
		}

		fileData, readErr := os.ReadFile(path)
		if readErr != nil {
			return &Error{
				Cause:     fmt.Errorf("reading file from %s: %w", path, ErrEncrypt),
				RootCause: readErr,
			}
		}

		encryptedFile, emitErr := e.encryptedBytes(path, fileData)
		if emitErr != nil {
			return &Error{
				Cause:     fmt.Errorf("emitting encrypted file %s: %w", path, ErrEncrypt),
				RootCause: emitErr,
			}
		}

		if writeErr := os.WriteFile(path, encryptedFile, fileInfo.Mode().Perm()); writeErr != nil {
			return &Error{
				Cause:     fmt.Errorf("writing encrypted file to %s: %w", path, ErrEncrypt),
				RootCause: emitErr,
			}
		}

		return nil
	}

	return wf
}
