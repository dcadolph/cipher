// Package pgp provides a cipher.KeyProvider backed by GPG fingerprints.
//
// Recipient identifiers are 40-character GPG key fingerprints (no
// spaces, no leading 0x). All fingerprints share a single key group.
//
// # Credentials
//
// The provider does not read key material itself. At encrypt and
// decrypt time, sops shells out to gpg, which reads the user's
// keyring. Make sure the gpg binary is on PATH and the relevant
// public keys are imported for encryption. Decryption requires the
// matching private keys.
//
// # Quick start
//
//	import (
//	    "github.com/dcadolph/cipher"
//	    "github.com/dcadolph/cipher/pgp"
//	)
//
//	kp, err := pgp.NewProvider("FBC7B9E2A4F9289AC0C1D4843D16CEE4A27381B4")
//	if err != nil { /* ... */ }
//	enc := cipher.NewEncoder(kp)
//
// PGP is the original sops backend. New projects should usually pick
// age or KMS-style backends instead, which have better tooling. PGP
// support is kept for compatibility with established teams.
package pgp

import (
	"context"
	"fmt"
	"strings"

	"github.com/getsops/sops/v3"
	sopspgp "github.com/getsops/sops/v3/pgp"

	"github.com/dcadolph/cipher"
	"github.com/dcadolph/cipher/internal/util"
)

// Provider is a cipher.KeyProvider that wraps each GPG fingerprint in a
// PGP master key. All fingerprints share a single key group.
type Provider struct {
	// Fingerprints is the list of GPG key fingerprints.
	Fingerprints []string
}

// NewProvider returns a cipher.KeyProvider for the given GPG
// fingerprints. Empty/whitespace-only entries are dropped. Returns an
// error if no usable fingerprints remain or any fingerprint is
// malformed. Each fingerprint must be 40 hex characters (an optional
// "0x" prefix and inner whitespace are accepted and normalized away).
func NewProvider(fingerprints ...string) (cipher.KeyProvider, error) {
	cleaned := util.TrimEmpty(fingerprints)
	if len(cleaned) == 0 {
		return nil, fmt.Errorf("cipher/pgp: at least one fingerprint required")
	}
	for i, fp := range cleaned {
		norm, err := normalizeFingerprint(fp)
		if err != nil {
			return nil, fmt.Errorf("cipher/pgp: fingerprint %q: %w", fp, err)
		}
		cleaned[i] = norm
	}
	return &Provider{Fingerprints: cleaned}, nil
}

// MustNewProvider wraps NewProvider and panics on error. Mirrors
// regexp.MustCompile and template.Must from the standard library:
// use only at init-time or in tests where construction failure is a
// developer error.
func MustNewProvider(fingerprints ...string) cipher.KeyProvider {
	kp, err := NewProvider(fingerprints...)
	if err != nil {
		panic(err)
	}
	return kp
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

// normalizeFingerprint trims whitespace and an optional "0x" prefix,
// then verifies the result is 40 hex characters. Letters are
// canonicalized to uppercase so callers cannot accidentally create
// distinct providers for the same key by varying hex case.
func normalizeFingerprint(fp string) (string, error) {
	fp = strings.ReplaceAll(strings.TrimSpace(fp), " ", "")
	fp = strings.TrimPrefix(strings.TrimPrefix(fp, "0x"), "0X")
	if len(fp) != 40 {
		return "", fmt.Errorf("expected 40 hex characters, got %d", len(fp))
	}
	for _, r := range fp {
		if !isHex(r) {
			return "", fmt.Errorf("non-hex character %q", r)
		}
	}
	return strings.ToUpper(fp), nil
}

// isHex reports whether r is a hex digit.
func isHex(r rune) bool {
	switch {
	case r >= '0' && r <= '9':
		return true
	case r >= 'a' && r <= 'f':
		return true
	case r >= 'A' && r <= 'F':
		return true
	}
	return false
}
