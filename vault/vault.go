// Package vault provides a cipher.KeyProvider backed by HashiCorp Vault Transit.
package vault

import (
	"context"
	"fmt"
	"strings"

	"github.com/getsops/sops/v3"
	"github.com/getsops/sops/v3/hcvault"

	"github.com/dcadolph/cipher"
)

// Provider is a cipher.KeyProvider that wraps each Vault Transit URI
// in a master key. All URIs share a single key group.
type Provider struct {
	// URIs is the list of Vault Transit URIs of the form
	// http(s)://vault.example.com:8200/v1/<engine>/keys/<keyName>
	URIs []string
}

// NewProvider returns a cipher.KeyProvider for the given Vault Transit
// URIs. Panics if no URIs are supplied or if any URI is malformed.
func NewProvider(uris ...string) cipher.KeyProvider {
	p, err := NewProviderE(uris...)
	if err != nil {
		panic(err.Error())
	}
	return p
}

// NewProviderE returns a cipher.KeyProvider for the given Vault Transit
// URIs and surfaces malformed-URI errors instead of panicking.
func NewProviderE(uris ...string) (cipher.KeyProvider, error) {
	cleaned := trimEmpty(uris)
	if len(cleaned) == 0 {
		return nil, fmt.Errorf("cipher/vault: at least one URI required")
	}
	for _, u := range cleaned {
		if _, err := hcvault.NewMasterKeyFromURI(u); err != nil {
			return nil, fmt.Errorf("cipher/vault: URI %q: %w", u, err)
		}
	}
	return &Provider{URIs: cleaned}, nil
}

// NewProviderFromCSV returns a Provider for a comma-separated list of
// URIs. Panics if csv contains no usable URIs or any URI is malformed.
func NewProviderFromCSV(csv string) cipher.KeyProvider {
	return NewProvider(strings.Split(csv, ",")...)
}

// KeyGroups returns a single key group with one Vault master key per
// URI. Implements cipher.KeyProvider.
func (p *Provider) KeyGroups(_ context.Context) ([]sops.KeyGroup, error) {
	if p == nil || len(p.URIs) == 0 {
		return nil, fmt.Errorf("cipher/vault: no URIs configured")
	}
	group := make(sops.KeyGroup, 0, len(p.URIs))
	for _, u := range p.URIs {
		mk, err := hcvault.NewMasterKeyFromURI(u)
		if err != nil {
			return nil, fmt.Errorf("cipher/vault: URI %q: %w", u, err)
		}
		group = append(group, mk)
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
