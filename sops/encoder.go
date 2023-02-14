package sops

import (
	"fmt"
	"os"
	"regexp"

	"github.com/dcadolph/cipher/encode"
	"go.mozilla.org/sops/v3"
	"go.mozilla.org/sops/v3/aes"
	"go.mozilla.org/sops/v3/cmd/sops/common"
	"go.mozilla.org/sops/v3/cmd/sops/formats"
	"go.mozilla.org/sops/v3/keyservice"
	"go.mozilla.org/sops/v3/version"
)

// encoder is the SOPS encryption encoder.
type encoder struct {
	cipher    sops.Cipher
	regex     *regexp.Regexp
	keyGroups []sops.KeyGroup
}

// Encoder returns a new SOPS encryption encode.Encoder.
//
// Regex is the encryption regex, which dictates what parts of a file should be encrypted.
//
// sops.KeyGroup dictate what type of encryption should be performed (e.g. age encryption if
// sops.KeyGroup is slice of age.MasterKey).
//
// Constructor panics if regex is nil or if key groups is empty.
func Encoder(regex *regexp.Regexp, keyGroups []sops.KeyGroup) encode.Encoder {

	if regex == nil {
		panic("encrypt walk: regex required")
	}

	if len(keyGroups) == 0 {
		panic("encrypt walk: key groups required")
	}

	return &encoder{
		cipher:    aes.NewCipher(),
		regex:     regex,
		keyGroups: keyGroups,
	}

}

// Encode SOPS-encrypts a file.
//
// If there is nothing to encrypt (e.g. there are no branches to encrypt, or nothing in the file
// matches the regular expression), the file data is returned unmodified.
//
// File input format and output format is based on a given file's extension. For more, see
// formats.FormatForPath.
//
// If a file has a YAML extension, but contains a JSON object, the result will be written as
// a YAML object. If a file has a JSON extension, but contains YAML, ErrEncode will be returned.
func (e *encoder) Encode(fileName string) ([]byte, error) {

	b, err := e.encryptedBytes(fileName)
	if err != nil {
		return nil, err
	}

	return b, nil
}

// encryptedBytes returns encrypted file data.
func (e *encoder) encryptedBytes(fileName string) ([]byte, error) {

	fileData, readErr := os.ReadFile(fileName)
	if readErr != nil {
		return nil, &Error{
			Cause:     fmt.Errorf("reading file from %s: %w", fileName, ErrEncode),
			RootCause: readErr,
		}
	}

	inputStore := common.StoreForFormat(formats.FormatForPath(fileName))
	outputStore := common.StoreForFormat(formats.FormatForPath(fileName))

	branches, branchesErr := inputStore.LoadPlainFile(fileData)
	if branchesErr != nil {
		return nil, &Error{
			Cause: fmt.Errorf(
				"loading plain file %s tree branches: %w",
				fileName,
				ErrEncode,
			),
			RootCause: branchesErr,
		}
	}

	// Nothing to encrypt.
	if len(branches) == 0 {
		return fileData, nil
	}

	for index, treeBranch := range branches {
		for _, treeItem := range treeBranch {
			if treeItem.Key == "sops" {
				return nil, &Error{
					Cause: fmt.Errorf(
						"%w: tree branch %d of %d in file %s is already encrypted",
						ErrEncode,
						index+1,
						len(branches),
						fileName,
					),
				}
			}
		}
	}

	tree := sops.Tree{
		Branches: branches,
		Metadata: sops.Metadata{
			KeyGroups:      e.keyGroups,
			EncryptedRegex: e.regex.String(),
			Version:        version.Version,
		},
		FilePath: fileName,
	}

	dataKey, genErr := tree.GenerateDataKeyWithKeyServices(
		[]keyservice.KeyServiceClient{
			keyservice.LocalClient{Server: keyservice.Server{Prompt: false}},
		},
	)
	if genErr != nil {
		return nil, &Error{
			Cause: fmt.Errorf("%w: failed to generate data key for %s", ErrEncode, fileName),
			//RootCause: errors.Join(genErr...),
		}
	}

	if err := common.EncryptTree(common.EncryptTreeOpts{
		DataKey: dataKey,
		Tree:    &tree,
		Cipher:  e.cipher,
	}); err != nil {
		return nil, &Error{
			Cause:     fmt.Errorf("%w: failed to encrypt %s", ErrEncode, fileName),
			RootCause: err,
		}
	}

	b, emitErr := outputStore.EmitEncryptedFile(tree)
	if emitErr != nil {
		return nil, &Error{
			Cause:     fmt.Errorf("emitting encrypted file %s: %w", fileName, ErrEncode),
			RootCause: emitErr,
		}
	}

	return b, nil
}
