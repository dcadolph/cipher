// Package age provides a cipher.KeyProvider backed by age recipients.
// It is the first-class KeyProvider for sops age encryption.
package age

import (
	"context"
	"fmt"
	"strings"

	"github.com/getsops/sops/v3"
	sopsage "github.com/getsops/sops/v3/age"
	"github.com/getsops/sops/v3/keys"

	"github.com/dcadolph/cipher"
)

// Provider is a cipher.KeyProvider that produces a single sops.KeyGroup
// populated with age master keys derived from public recipients.
type Provider struct {
	// Recipients holds the age recipient strings (e.g. "age1...") used
	// to wrap the per-file data key.
	Recipients []string
}

// NewProvider returns a cipher.KeyProvider for the given age recipients.
// All recipients populate a single key group, matching sops' typical
// age usage where any holder of a corresponding identity can decrypt.
// Panics if no recipients are supplied.
func NewProvider(recipients ...string) cipher.KeyProvider {
	if len(recipients) == 0 {
		panic("cipher/age: NewProvider: at least one recipient required")
	}
	cleaned := cleanRecipients(recipients)
	if len(cleaned) == 0 {
		panic("cipher/age: NewProvider: all recipients were empty after trimming")
	}
	return &Provider{Recipients: cleaned}
}

// KeyGroups returns a single key group with one age master key per
// recipient. Implements cipher.KeyProvider.
func (p *Provider) KeyGroups(_ context.Context) ([]sops.KeyGroup, error) {
	if p == nil || len(p.Recipients) == 0 {
		return nil, fmt.Errorf("cipher/age: no recipients configured")
	}
	group := make(sops.KeyGroup, 0, len(p.Recipients))
	for _, r := range p.Recipients {
		mk, err := sopsage.MasterKeyFromRecipient(r)
		if err != nil {
			return nil, fmt.Errorf("cipher/age: recipient %q: %w", r, err)
		}
		group = append(group, keys.MasterKey(mk))
	}
	return []sops.KeyGroup{group}, nil
}

// NewProviderFromCSV returns a cipher.KeyProvider for a comma-separated
// list of age recipients, matching the form accepted by sops command-line
// arguments. Panics if csv contains no usable recipients.
func NewProviderFromCSV(csv string) cipher.KeyProvider {
	parts := strings.Split(csv, ",")
	return NewProvider(parts...)
}

// cleanRecipients trims whitespace and drops empty entries.
func cleanRecipients(in []string) []string {
	out := make([]string, 0, len(in))
	for _, r := range in {
		r = strings.TrimSpace(r)
		if r != "" {
			out = append(out, r)
		}
	}
	return out
}
