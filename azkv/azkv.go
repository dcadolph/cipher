// Package azkv provides a cipher.KeyProvider backed by Azure Key Vault.
//
// Recipient identifiers are Azure Key Vault key URLs of the form
//
//	https://<vault>.vault.azure.net/keys/<keyName>/<keyVersion>
//
// All URLs share a single key group.
//
// # Credentials
//
// The provider does not read Azure credentials itself. At encrypt and
// decrypt time, sops uses the Azure default credential chain:
//
//   - AZURE_CLIENT_ID / AZURE_CLIENT_SECRET / AZURE_TENANT_ID env
//   - managed identity (when running in Azure)
//   - the az CLI credentials
//
// # Quick start
//
//	import (
//	    "github.com/dcadolph/cipher"
//	    "github.com/dcadolph/cipher/azkv"
//	)
//
//	kp, err := azkv.NewProvider(
//	    "https://kv-prod.vault.azure.net/keys/sops/abcdef",
//	)
//	if err != nil { /* ... */ }
//	enc := cipher.NewEncoder(kp)
package azkv

import (
	"context"
	"fmt"

	"github.com/getsops/sops/v3"
	sopsazkv "github.com/getsops/sops/v3/azkv"

	"github.com/dcadolph/cipher"
	"github.com/dcadolph/cipher/internal/util"
)

// Provider is a cipher.KeyProvider that wraps each Azure Key Vault key
// URL in a master key. All URLs share a single key group.
type Provider struct {
	// URLs is the list of Azure Key Vault key URLs of the form
	// https://<vault>.vault.azure.net/keys/<keyName>/<keyVersion>
	URLs []string
}

// NewProvider returns a cipher.KeyProvider for the given Azure Key
// Vault URLs. Empty/whitespace-only entries are dropped. Returns an
// error if no usable URLs remain or any URL is malformed.
func NewProvider(urls ...string) (cipher.KeyProvider, error) {
	cleaned := util.TrimEmpty(urls)
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

// MustNewProvider wraps NewProvider and panics on error. Mirrors
// regexp.MustCompile and template.Must from the standard library:
// use only at init-time or in tests where construction failure is a
// developer error.
func MustNewProvider(urls ...string) cipher.KeyProvider {
	kp, err := NewProvider(urls...)
	if err != nil {
		panic(err)
	}
	return kp
}

// KeyGroups returns a single key group with one Azure KV master key
// per URL. Implements cipher.KeyProvider.
//
// Master keys are constructed fresh on every call rather than cached
// at construction time. sops master keys carry mutable state (the
// per-operation EncryptedDataKey) so a single instance cannot safely
// service concurrent Encode operations, which is the common case for
// a long-lived Encoder shared across goroutines. URL parsing is
// cheap relative to the Azure round-trip, so the fresh allocation is
// not on any hot path.
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
