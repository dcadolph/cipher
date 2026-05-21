package cipher

import (
	"context"

	"github.com/getsops/sops/v3"
)

// KeyProvider returns the sops key groups used by an Encoder to wrap
// the per-file data key. Each backend (age, AWS KMS, GCP KMS, Vault,
// PGP, Azure Key Vault) implements KeyProvider in its own subpackage.
//
// The return type is sops.KeyGroup, the same shape sops uses internally.
// This keeps backend interop straightforward and lets callers compose
// groups across providers.
type KeyProvider interface {
	// KeyGroups returns the key groups to use, in priority order.
	// Implementations should return a non-empty slice or a non-nil error.
	KeyGroups(ctx context.Context) ([]sops.KeyGroup, error)
}

// KeyProviderFunc adapts a plain function to KeyProvider.
type KeyProviderFunc func(ctx context.Context) ([]sops.KeyGroup, error)

// KeyGroups calls f.
func (f KeyProviderFunc) KeyGroups(ctx context.Context) ([]sops.KeyGroup, error) {
	return f(ctx)
}

// StaticKeyProvider returns a KeyProvider that always yields the given
// groups. Useful for tests and call-site composition.
func StaticKeyProvider(groups ...sops.KeyGroup) KeyProvider {
	g := append([]sops.KeyGroup(nil), groups...)
	return KeyProviderFunc(func(context.Context) ([]sops.KeyGroup, error) {
		return g, nil
	})
}

// ChainKeyProviders returns a KeyProvider that concatenates the groups
// from each underlying provider, in order. Errors from any underlying
// provider abort the chain.
func ChainKeyProviders(providers ...KeyProvider) KeyProvider {
	return KeyProviderFunc(func(ctx context.Context) ([]sops.KeyGroup, error) {
		var out []sops.KeyGroup
		for _, p := range providers {
			groups, err := p.KeyGroups(ctx)
			if err != nil {
				return nil, err
			}
			out = append(out, groups...)
		}
		return out, nil
	})
}
