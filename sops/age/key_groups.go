package age

import (
	"fmt"

	"github.com/dcadolph/cipher/sops"
	stdsops "go.mozilla.org/sops/v3"
	"go.mozilla.org/sops/v3/age"
	"go.mozilla.org/sops/v3/keys"
)

// KeyGroups returns slice of sops.KeyGroup using given age public keys.
func KeyGroups(agePublicKey string) ([]stdsops.KeyGroup, error) {

	masterKey, mkErr := age.MasterKeysFromRecipients(agePublicKey)
	if mkErr != nil {
		return nil, &sops.Error{
			Cause:     fmt.Errorf("%w: failed to get age master key", sops.ErrGetKey),
			RootCause: mkErr,
		}
	}

	return []stdsops.KeyGroup{[]keys.MasterKey{masterKey[0]}}, nil
}
