package sops

import (
	"fmt"
	"os"

	"github.com/dcadolph/cipher/decode"
	"go.mozilla.org/sops/v3"
	"go.mozilla.org/sops/v3/aes"
	"go.mozilla.org/sops/v3/cmd/sops/common"
	"go.mozilla.org/sops/v3/cmd/sops/formats"
	"go.mozilla.org/sops/v3/keyservice"
)

// Decoder returns a SOPS decode.Decoder.
//
// Decoder works "out of the box" for most SOPS-encrypted data, but for age key encryption, consumer
// must call age.Decoder.
func Decoder() decode.Decoder {

	f := func(fileName string) ([]byte, error) {

		cipher := aes.NewCipher()

		inputStore := common.StoreForFormat(formats.FormatForPath(fileName))
		outputStore := common.StoreForFormat(formats.FormatForPath(fileName))

		keyServices := []keyservice.KeyServiceClient{
			keyservice.LocalClient{Server: keyservice.Server{Prompt: false}},
		}

		var tree sops.Tree
		var err error

		fileData, readErr := os.ReadFile(fileName)
		if readErr != nil {
			return nil, &Error{
				Cause:     fmt.Errorf("reading file %s: %w", fileName, ErrDecode),
				RootCause: readErr,
			}
		}

		tree, err = inputStore.LoadEncryptedFile(fileData)
		if err != nil {
			return nil, &Error{
				Cause: fmt.Errorf(
					"loading encrypted file data for %s: %w",
					fileName,
					ErrDecode,
				),
				RootCause: err,
			}
		}

		tree.FilePath = fileName

		if _, decryptErr := common.DecryptTree(common.DecryptTreeOpts{
			Cipher:      cipher,
			IgnoreMac:   false,
			Tree:        &tree,
			KeyServices: keyServices,
		}); decryptErr != nil {
			return nil, &Error{
				Cause: fmt.Errorf(
					"decrypting file data for %s: %w",
					fileName,
					ErrDecode,
				),
				RootCause: decryptErr,
			}
		}

		decryptedFile, emitErr := outputStore.EmitPlainFile(tree.Branches)
		if emitErr != nil {
			return nil, &Error{
				Cause: fmt.Errorf(
					"emitting plain file data for %s: %w",
					fileName,
					ErrDecode,
				),
				RootCause: emitErr,
			}
		}

		return decryptedFile, nil
	}

	return decode.DecoderFunc(f)
}
