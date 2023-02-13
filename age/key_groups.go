package age

import (
	"fmt"

	"go.mozilla.org/sops/v3"
	"go.mozilla.org/sops/v3/age"
	"go.mozilla.org/sops/v3/keys"
)

// AgeKeyGroups returns slice of sops.KeyGroup using given age public keys.
func AgeKeyGroups(agePublicKey ...string) ([]sops.KeyGroup, error) {

	var masterKeys []keys.MasterKey

	for _, key := range agePublicKey {
		masterKey, mkErr := age.MasterKeysFromRecipients(key)
		if mkErr != nil {
			return nil, &Error{
				Cause:     fmt.Errorf("%w: failed to get age master key", ErrGetKey),
				RootCause: mkErr,
			}
		}
		masterKeys = append(masterKeys, masterKey[0])
	}

	return []sops.KeyGroup{masterKeys}, nil
}
