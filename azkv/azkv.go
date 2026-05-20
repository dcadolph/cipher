// Package azkv provides a cipher.KeyProvider backed by Azure Key Vault.
package azkv

import (
	"context"
	"fmt"
	"strings"

	"github.com/getsops/sops/v3"
	sopsazkv "github.com/getsops/sops/v3/azkv"

	"github.com/dcadolph/cipher"
)

// Provider is a cipher.KeyProvider that wraps each Azure Key Vault key
// URL in a master key. All URLs share a single key group.
type Provider struct {
	// URLs is the list of Azure Key Vault key URLs of the form
	// https://<vault>.vault.azure.net/keys/<keyName>/<keyVersion>
	URLs []string
}

// NewProvider returns a cipher.KeyProvider for the given Azure Key Vault
// URLs. Panics if no URLs are supplied or if any URL is malformed.
func NewProvider(urls ...string) cipher.KeyProvider {
	p, err := NewProviderE(urls...)
	if err != nil {
		panic(err.Error())
	}
	return p
}

// NewProviderE returns a cipher.KeyProvider for the given Azure Key
// Vault URLs and surfaces malformed-URL errors instead of panicking.
func NewProviderE(urls ...string) (cipher.KeyProvider, error) {
	cleaned := trimEmpty(urls)
	if len(cleaned) == 0 {
		return nil, fmt.Errorf("cipher/azkv: at least one URL required")
	}
	for _, u := range cleaned {
		if _, err := sopsazkv.NewMasterKeyFromURL(u); err != nil {
			return nil, fmt.Errorf("cipher/azkv: URL %q: %w", u, err)
		}
	}
	return &Provider{URLs: cleaned}, nil
}

// NewProviderFromCSV returns a Provider for a comma-separated list of
// URLs. Panics if csv contains no usable URLs or any URL is malformed.
func NewProviderFromCSV(csv string) cipher.KeyProvider {
	return NewProvider(strings.Split(csv, ",")...)
}

// KeyGroups returns a single key group with one Azure KV master key
// per URL. Implements cipher.KeyProvider.
func (p *Provider) KeyGroups(_ context.Context) ([]sops.KeyGroup, error) {
	if p == nil || len(p.URLs) == 0 {
		return nil, fmt.Errorf("cipher/azkv: no URLs configured")
	}
	group := make(sops.KeyGroup, 0, len(p.URLs))
	for _, u := range p.URLs {
		mk, err := sopsazkv.NewMasterKeyFromURL(u)
		if err != nil {
			return nil, fmt.Errorf("cipher/azkv: URL %q: %w", u, err)
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
