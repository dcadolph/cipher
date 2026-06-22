// Package kms provides a cipher.KeyProvider backed by AWS KMS.
//
// Recipient identifiers are AWS KMS key ARNs of the form
//
//	arn:aws:kms:<region>:<account>:key/<key-id>
//
// or
//
//	arn:aws:kms:<region>:<account>:alias/<alias-name>
//
// All ARNs share a single key group. Any one identity holding access
// to any ARN decrypts.
//
// # Credentials
//
// The provider does not read AWS credentials itself. At encrypt and
// decrypt time, sops resolves them through the default AWS SDK chain:
//
//   - shared credentials file (~/.aws/credentials, ~/.aws/config)
//   - environment (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, etc.)
//   - IAM Roles for EC2 / ECS / EKS (IRSA)
//   - assume-role chains via Role
//
// Use [ProviderOptions.Profile] to pin a shared-credentials profile.
// Use [ProviderOptions.Role] to assume a role for KMS operations.
//
// # Encryption context
//
// AWS KMS encryption context is a map of key-value pairs that must
// match at encrypt and decrypt time. It is used to bind a file to a
// deployment, environment, or tenant. Pass it via
// [ProviderOptions.EncryptionContext]. The same context must be
// supplied at decryption time.
//
// # Quick start
//
//	import (
//	    "github.com/dcadolph/cipher"
//	    "github.com/dcadolph/cipher/kms"
//	)
//
//	kp, err := kms.NewProvider(kms.ProviderOptions{},
//	    "arn:aws:kms:us-east-1:123456789012:key/...")
//	if err != nil { /* ... */ }
//	enc := cipher.NewEncoder(kp)
//
//	// With encryption context and a profile.
//	kp, err = kms.NewProvider(kms.ProviderOptions{
//	    EncryptionContext: map[string]string{"env": "prod"},
//	    Profile:           "deploy",
//	}, "arn:aws:kms:us-east-1:123456789012:key/...")
package kms

import (
	"context"
	"fmt"
	"strings"

	"github.com/getsops/sops/v3"
	sopskms "github.com/getsops/sops/v3/kms"

	"github.com/dcadolph/cipher"
	"github.com/dcadolph/cipher/internal/strutil"
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
// using default credential chain and no encryption context. Mirrors
// the NewProvider shape of the other cipher backends. Use
// NewProviderWith when an encryption context, role, or profile is
// required.
func NewProvider(arns ...string) (cipher.KeyProvider, error) {
	return NewProviderWith(ProviderOptions{}, arns...)
}

// MustNewProvider wraps NewProvider and panics on error. Mirrors
// regexp.MustCompile and template.Must from the standard library.
func MustNewProvider(arns ...string) cipher.KeyProvider {
	kp, err := NewProvider(arns...)
	if err != nil {
		panic(err)
	}
	return kp
}

// NewProviderWith returns a cipher.KeyProvider for the given AWS KMS
// ARNs using opts to configure credentials and encryption context.
// Pass a zero-valued ProviderOptions when no extra configuration is
// needed (or use NewProvider). Empty/whitespace-only ARN entries are
// dropped. Returns an error if no usable ARNs remain, any ARN is
// malformed, the role ARN is malformed, or the encryption context
// fails validation.
func NewProviderWith(opts ProviderOptions, arns ...string) (cipher.KeyProvider, error) {
	cleaned := strutil.TrimEmpty(arns)
	if len(cleaned) == 0 {
		return nil, fmt.Errorf("cipher/kms: at least one ARN required")
	}
	for _, arn := range cleaned {
		if err := validateARN(arn); err != nil {
			return nil, fmt.Errorf("cipher/kms: ARN %q: %w", arn, err)
		}
	}
	if opts.Role != "" {
		if err := validateRoleARN(opts.Role); err != nil {
			return nil, fmt.Errorf("cipher/kms: Role %q: %w", opts.Role, err)
		}
	}
	if err := validateEncryptionContext(opts.EncryptionContext); err != nil {
		return nil, fmt.Errorf("cipher/kms: %w", err)
	}
	return &Provider{ARNs: cleaned, Options: opts}, nil
}

// MustNewProviderWith wraps NewProviderWith and panics on error.
func MustNewProviderWith(opts ProviderOptions, arns ...string) cipher.KeyProvider {
	kp, err := NewProviderWith(opts, arns...)
	if err != nil {
		panic(err)
	}
	return kp
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

// validateARN returns an error if arn is not shaped like an AWS KMS
// ARN: arn:aws[-partition]:kms:<region>:<account>:(key|alias)/<rest>.
func validateARN(arn string) error {
	parts := strings.SplitN(arn, ":", 6)
	if len(parts) != 6 {
		return fmt.Errorf("expected 6 colon-separated parts, got %d", len(parts))
	}
	if parts[0] != "arn" {
		return fmt.Errorf("missing arn: prefix")
	}
	if !strings.HasPrefix(parts[1], "aws") {
		return fmt.Errorf("partition %q does not begin with aws", parts[1])
	}
	if parts[2] != "kms" {
		return fmt.Errorf("service %q is not kms", parts[2])
	}
	if parts[3] == "" {
		return fmt.Errorf("region is empty")
	}
	if parts[4] == "" {
		return fmt.Errorf("account is empty")
	}
	resource := parts[5]
	if !strings.HasPrefix(resource, "key/") && !strings.HasPrefix(resource, "alias/") {
		return fmt.Errorf("resource %q does not start with key/ or alias/", resource)
	}
	return nil
}

// maxEncryptionContextEntries caps the encryption context map. AWS
// KMS accepts up to 10 entries; we mirror that to fail loudly at
// construction time.
const maxEncryptionContextEntries = 10

// validateEncryptionContext returns an error if the AWS KMS encryption
// context contains entries that AWS would reject: empty keys/values,
// control characters, or more than maxEncryptionContextEntries entries.
// AWS treats the context as UTF-8 strings; we additionally reject
// control characters because they create logging and audit hazards.
func validateEncryptionContext(ctx map[string]string) error {
	if len(ctx) == 0 {
		return nil
	}
	if len(ctx) > maxEncryptionContextEntries {
		return fmt.Errorf("EncryptionContext has %d entries (max %d)",
			len(ctx), maxEncryptionContextEntries)
	}
	for k, v := range ctx {
		if k == "" {
			return fmt.Errorf("EncryptionContext: key is empty")
		}
		if v == "" {
			return fmt.Errorf("EncryptionContext key %q: value is empty", k)
		}
		if hasControlChar(k) {
			return fmt.Errorf("EncryptionContext key %q contains a control character", k)
		}
		if hasControlChar(v) {
			return fmt.Errorf("EncryptionContext key %q: value contains a control character", k)
		}
	}
	return nil
}

// hasControlChar reports whether s contains any C0 or C1 control
// character.
func hasControlChar(s string) bool {
	for _, r := range s {
		if r < 0x20 || (r >= 0x7F && r <= 0x9F) {
			return true
		}
	}
	return false
}

// validateRoleARN returns an error if arn is not shaped like an AWS IAM
// role ARN.
func validateRoleARN(arn string) error {
	parts := strings.SplitN(arn, ":", 6)
	if len(parts) != 6 {
		return fmt.Errorf("expected 6 colon-separated parts, got %d", len(parts))
	}
	if parts[0] != "arn" || !strings.HasPrefix(parts[1], "aws") {
		return fmt.Errorf("not an AWS ARN")
	}
	if parts[2] != "iam" {
		return fmt.Errorf("service %q is not iam", parts[2])
	}
	if !strings.HasPrefix(parts[5], "role/") {
		return fmt.Errorf("resource %q does not start with role/", parts[5])
	}
	return nil
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
