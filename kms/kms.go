// Package kms provides a cipher.KeyProvider backed by AWS KMS.
package kms

import (
	"context"
	"fmt"
	"strings"

	"github.com/getsops/sops/v3"
	sopskms "github.com/getsops/sops/v3/kms"

	"github.com/dcadolph/cipher"
)

// ProviderOptions tunes Provider construction.
type ProviderOptions struct {
	// EncryptionContext is the AWS KMS encryption context map. The same
	// context must be supplied at decryption time.
	EncryptionContext map[string]string
	// Profile is the AWS shared-credentials profile to use. Empty uses
	// the default credential chain.
	Profile string
	// Role is the IAM role ARN to assume for KMS operations. Empty
	// uses the caller's identity.
	Role string
}

// Provider is a cipher.KeyProvider that wraps each ARN in an AWS KMS
// master key. All ARNs share a single key group, so any one identity
// holding access to any ARN can decrypt.
type Provider struct {
	// ARNs is the list of AWS KMS key ARNs used for encryption.
	ARNs []string
	// Options carries optional encryption context, profile, and role.
	Options ProviderOptions
}

// NewProvider returns a cipher.KeyProvider for the given AWS KMS ARNs
// using the default credential chain and no encryption context.
// Panics if no ARNs are supplied.
func NewProvider(arns ...string) cipher.KeyProvider {
	return NewProviderWith(ProviderOptions{}, arns...)
}

// NewProviderWith returns a cipher.KeyProvider with explicit options.
// Panics if no ARNs are supplied.
func NewProviderWith(opts ProviderOptions, arns ...string) cipher.KeyProvider {
	cleaned := trimEmpty(arns)
	if len(cleaned) == 0 {
		panic("cipher/kms: NewProviderWith: at least one ARN required")
	}
	return &Provider{ARNs: cleaned, Options: opts}
}

// NewProviderFromCSV returns a Provider for a comma-separated list of ARNs.
// Panics if csv contains no usable ARNs.
func NewProviderFromCSV(csv string) cipher.KeyProvider {
	return NewProvider(strings.Split(csv, ",")...)
}

// KeyGroups returns a single key group with one KMS master key per ARN.
// Implements cipher.KeyProvider.
func (p *Provider) KeyGroups(_ context.Context) ([]sops.KeyGroup, error) {
	if p == nil || len(p.ARNs) == 0 {
		return nil, fmt.Errorf("cipher/kms: no ARNs configured")
	}
	ctxPtr := contextToPtrMap(p.Options.EncryptionContext)
	group := make(sops.KeyGroup, 0, len(p.ARNs))
	for _, arn := range p.ARNs {
		mk := sopskms.NewMasterKey(arn, p.Options.Role, ctxPtr)
		if p.Options.Profile != "" {
			mk.AwsProfile = p.Options.Profile
		}
		group = append(group, mk)
	}
	return []sops.KeyGroup{group}, nil
}

// contextToPtrMap converts a string map to the *string map form sops
// requires for KMS encryption context.
func contextToPtrMap(in map[string]string) map[string]*string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]*string, len(in))
	for k, v := range in {
		v := v
		out[k] = &v
	}
	return out
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
