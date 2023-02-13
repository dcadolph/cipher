package decrypt

import (
	"fmt"

	"go.mozilla.org/sops/v3"
	"go.mozilla.org/sops/v3/aes"
	"go.mozilla.org/sops/v3/cmd/sops/common"
	"go.mozilla.org/sops/v3/cmd/sops/formats"
	"go.mozilla.org/sops/v3/keyservice"
)

// sopsDecode decodes a sops-encoded file and returns its plaintext file data.
func sopsDecode(fileName string, fileData []byte) ([]byte, error) {

	cipher := aes.NewCipher()

	inputStore := common.StoreForFormat(formats.FormatForPath(fileName))
	outputStore := common.StoreForFormat(formats.FormatForPath(fileName))

	keyServices := []keyservice.KeyServiceClient{
		keyservice.LocalClient{Server: keyservice.Server{Prompt: false}},
	}

	var tree sops.Tree
	var err error

	tree, err = inputStore.LoadEncryptedFile(fileData)
	if err != nil {
		return nil, &Error{
			Cause:     fmt.Errorf("loading encrypted file data for %s: %w", fileName, ErrDecrypt),
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
			Cause:     fmt.Errorf("decrypting file data for %s: %w", fileName, ErrDecrypt),
			RootCause: decryptErr,
		}
	}

	decryptedFile, emitErr := outputStore.EmitPlainFile(tree.Branches)
	if emitErr != nil {
		return nil, &Error{
			Cause:     fmt.Errorf("emitting plain file data for %s: %w", fileName, ErrDecrypt),
			RootCause: emitErr,
		}
	}

	return decryptedFile, nil
}
