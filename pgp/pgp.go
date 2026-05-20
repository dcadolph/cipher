// Package pgp provides a cipher.KeyProvider backed by GPG fingerprints.
package pgp

import (
	"context"
	"fmt"
	"strings"

	"github.com/getsops/sops/v3"
	sopspgp "github.com/getsops/sops/v3/pgp"

	"github.com/dcadolph/cipher"
)

// Provider is a cipher.KeyProvider that wraps each GPG fingerprint in a
// PGP master key. All fingerprints share a single key group.
type Provider struct {
	// Fingerprints is the list of GPG key fingerprints.
	Fingerprints []string
}

// NewProvider returns a cipher.KeyProvider for the given GPG
// fingerprints. Panics if no fingerprints are supplied.
func NewProvider(fingerprints ...string) cipher.KeyProvider {
	cleaned := trimEmpty(fingerprints)
	if len(cleaned) == 0 {
		panic("cipher/pgp: NewProvider: at least one fingerprint required")
	}
	return &Provider{Fingerprints: cleaned}
}

// NewProviderFromCSV returns a Provider for a comma-separated list of
// fingerprints. Panics if csv contains no usable fingerprints.
func NewProviderFromCSV(csv string) cipher.KeyProvider {
	return NewProvider(strings.Split(csv, ",")...)
}

// KeyGroups returns a single key group with one PGP master key per
// fingerprint. Implements cipher.KeyProvider.
func (p *Provider) KeyGroups(_ context.Context) ([]sops.KeyGroup, error) {
	if p == nil || len(p.Fingerprints) == 0 {
		return nil, fmt.Errorf("cipher/pgp: no fingerprints configured")
	}
	group := make(sops.KeyGroup, 0, len(p.Fingerprints))
	for _, fp := range p.Fingerprints {
		group = append(group, sopspgp.NewMasterKeyFromFingerprint(fp))
	}
	return []sops.KeyGroup{group}, nil
}

// trimEmpty returns in with empty/whitespace-only entries removed.
func trimEmpty(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}
