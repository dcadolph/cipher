// Package vault provides a cipher.KeyProvider backed by HashiCorp Vault Transit.
//
// Recipient identifiers are Vault Transit URIs of the form
//
//	http(s)://<host>:<port>/v1/<engine>/keys/<keyName>
//
// where <engine> is the path of a mounted Transit secrets engine and
// <keyName> is a named encryption key on that engine. All URIs share a
// single key group.
//
// # Credentials
//
// The provider does not read Vault credentials itself. At encrypt and
// decrypt time, sops uses the standard Vault env:
//
//   - VAULT_TOKEN
//   - VAULT_ADDR (when the URI is host-relative)
//   - ~/.vault-token written by `vault login`
//
// # Quick start
//
//	import (
//	    "github.com/dcadolph/cipher"
//	    "github.com/dcadolph/cipher/vault"
//	)
//
//	kp, err := vault.NewProvider(
//	    "https://vault.example.com:8200/v1/transit/keys/sops",
//	)
//	if err != nil { /* ... */ }
//	enc := cipher.NewEncoder(kp)
package vault

import (
	"context"
	"fmt"

	"github.com/getsops/sops/v3"
	"github.com/getsops/sops/v3/hcvault"

	"github.com/dcadolph/cipher"
	"github.com/dcadolph/cipher/internal/util"
)

// Provider is a cipher.KeyProvider that wraps each Vault Transit URI
// in a master key. All URIs share a single key group.
type Provider struct {
	// URIs is the list of Vault Transit URIs of the form
	// http(s)://vault.example.com:8200/v1/<engine>/keys/<keyName>
	URIs []string
}

// NewProvider returns a cipher.KeyProvider for the given Vault Transit
// URIs. Empty/whitespace-only entries are dropped. Returns an error if
// no usable URIs remain or any URI is malformed.
func NewProvider(uris ...string) (cipher.KeyProvider, error) {
	cleaned := util.TrimEmpty(uris)
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

// MustNewProvider wraps NewProvider and panics on error. Mirrors
// regexp.MustCompile and template.Must from the standard library:
// use only at init-time or in tests where construction failure is a
// developer error.
func MustNewProvider(uris ...string) cipher.KeyProvider {
	kp, err := NewProvider(uris...)
	if err != nil {
		panic(err)
	}
	return kp
}

// KeyGroups returns a single key group with one Vault master key per
// URI. Implements cipher.KeyProvider.
//
// Master keys are constructed fresh on every call rather than cached
// at construction time. sops master keys carry mutable state (the
// per-operation EncryptedDataKey) so a single instance cannot safely
// service concurrent Encode operations, which is the common case for
// a long-lived Encoder shared across goroutines. URI parsing is
// cheap relative to the network round-trip to Vault, so the fresh
// allocation is not on any hot path.
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
