// Package cipher_test pins the on-disk identity format that
// RemoveRecipient uses to match keys for removal. The identity is the
// sops master key's ToString() output. Sops treats ToString as a
// display method and does not promise the format is stable across
// versions. RemoveRecipient cares about exact matching, so a silent
// format change in sops would either fail to match (returns "no
// matching recipients found") or match the wrong key.
//
// These tests capture the expected output per backend so a sops
// upgrade that changes formatting breaks CI here instead of a user's
// rotation.
package cipher_test

import (
	"context"
	"testing"

	"github.com/getsops/sops/v3/keys"

	"github.com/dcadolph/cipher"
	"github.com/dcadolph/cipher/age"
	"github.com/dcadolph/cipher/azkv"
	"github.com/dcadolph/cipher/gcpkms"
	"github.com/dcadolph/cipher/kms"
	"github.com/dcadolph/cipher/pgp"
	"github.com/dcadolph/cipher/vault"
)

// TestRecipientIdentityFormat asserts the ToString() output of each
// backend's master key. If a sops upgrade changes any of these strings
// RemoveRecipient stops matching and the test fails loudly.
func TestRecipientIdentityFormat(t *testing.T) {
	t.Parallel()
	tests := []struct {
		Name  string
		Want  string
		Build func() (cipher.KeyProvider, error)
	}{
		{ // Test 0: age recipient round-trips verbatim.
			Name: "age",
			Want: "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p",
			Build: func() (cipher.KeyProvider, error) {
				return age.NewProvider("age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p")
			},
		},
		{ // Test 1: aws kms arn round-trips verbatim.
			Name: "aws-kms",
			Want: "arn:aws:kms:us-east-1:111122223333:key/abcd1234-ef56-7890-abcd-ef1234567890",
			Build: func() (cipher.KeyProvider, error) {
				return kms.NewProvider(
					"arn:aws:kms:us-east-1:111122223333:key/abcd1234-ef56-7890-abcd-ef1234567890",
				)
			},
		},
		{ // Test 2: gcp kms resource id round-trips verbatim.
			Name: "gcp-kms",
			Want: "projects/p/locations/us/keyRings/r/cryptoKeys/k",
			Build: func() (cipher.KeyProvider, error) {
				return gcpkms.NewProvider("projects/p/locations/us/keyRings/r/cryptoKeys/k")
			},
		},
		{ // Test 3: vault transit uri round-trips verbatim.
			Name: "vault",
			Want: "https://vault.example.com/v1/transit/keys/cipher",
			Build: func() (cipher.KeyProvider, error) {
				return vault.NewProvider("https://vault.example.com/v1/transit/keys/cipher")
			},
		},
		{ // Test 4: azure key vault url round-trips verbatim.
			Name: "azure-keyvault",
			Want: "https://kv.vault.azure.net/keys/cipher/abc123",
			Build: func() (cipher.KeyProvider, error) {
				return azkv.NewProvider("https://kv.vault.azure.net/keys/cipher/abc123")
			},
		},
		{ // Test 5: pgp fingerprint round-trips verbatim.
			Name: "pgp",
			Want: "AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555",
			Build: func() (cipher.KeyProvider, error) {
				return pgp.NewProvider("AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555")
			},
		},
	}
	for i, tc := range tests {
		t.Run(tc.Name, func(t *testing.T) {
			t.Parallel()
			kp, err := tc.Build()
			if err != nil {
				t.Fatalf("Test %d (%s): build: %v", i, tc.Name, err)
			}
			got, err := firstMasterKeyToString(kp)
			if err != nil {
				t.Fatalf("Test %d (%s): key groups: %v", i, tc.Name, err)
			}
			if got != tc.Want {
				t.Errorf("Test %d (%s): ToString mismatch\n want: %q\n  got: %q\nsops may have changed the format used by RemoveRecipient",
					i, tc.Name, tc.Want, got)
			}
		})
	}
}

// firstMasterKeyToString returns the ToString() output of the first
// master key in the first key group returned by kp.
func firstMasterKeyToString(kp cipher.KeyProvider) (string, error) {
	groups, err := kp.KeyGroups(context.Background())
	if err != nil {
		return "", err
	}
	for _, g := range groups {
		for _, k := range g {
			return k.ToString(), nil
		}
	}
	return "", errEmptyKeyGroups
}

// errEmptyKeyGroups is returned when a provider yields no master keys.
var errEmptyKeyGroups = &emptyKeyGroupsError{}

// emptyKeyGroupsError signals that the provider returned no key groups
// or only empty ones.
type emptyKeyGroupsError struct{}

// Error implements error.
func (*emptyKeyGroupsError) Error() string { return "provider returned no master keys" }

// Compile-time check that the sops master key type still exposes
// ToString. Keeps a future sops refactor from silently breaking the
// assumption RemoveRecipient depends on.
var _ = func(k keys.MasterKey) string { return k.ToString() }

// TestBackendParityRejectsEmpty asserts every backend's NewProvider
// rejects an empty or whitespace-only recipient list. Catches drift
// if one backend silently allows zero usable recipients while another
// errors.
func TestBackendParityRejectsEmpty(t *testing.T) {
	t.Parallel()
	type ctor func(...string) (cipher.KeyProvider, error)
	backends := []struct {
		Name string
		New  ctor
	}{
		// Test 0: age.
		{"age", age.NewProvider},
		// Test 1: aws kms.
		{"aws-kms", kms.NewProvider},
		// Test 2: gcp kms.
		{"gcp-kms", gcpkms.NewProvider},
		// Test 3: vault.
		{"vault", vault.NewProvider},
		// Test 4: azure key vault.
		{"azure-keyvault", azkv.NewProvider},
		// Test 5: pgp.
		{"pgp", pgp.NewProvider},
	}
	for i, b := range backends {
		t.Run(b.Name+"/no-args", func(t *testing.T) {
			t.Parallel()
			if _, err := b.New(); err == nil {
				t.Errorf("Test %d (%s): expected error for empty input", i, b.Name)
			}
		})
		t.Run(b.Name+"/whitespace", func(t *testing.T) {
			t.Parallel()
			if _, err := b.New("  ", "\t", ""); err == nil {
				t.Errorf("Test %d (%s): expected error for whitespace-only input",
					i, b.Name)
			}
		})
	}
}

// TestBackendParityShape asserts every backend's KeyGroups returns
// exactly one key group with len(recipients) master keys. Sops itself
// supports multi-group, but cipher's per-backend providers all
// flatten into a single group.
func TestBackendParityShape(t *testing.T) {
	t.Parallel()
	type ctor func(...string) (cipher.KeyProvider, error)
	type sample struct {
		Name string
		New  ctor
		A, B string
	}
	idA := age.MustGenerateIdentity()
	idB := age.MustGenerateIdentity()
	samples := []sample{
		{ // Test 0: age.
			Name: "age",
			New:  age.NewProvider,
			A:    idA.Recipient,
			B:    idB.Recipient,
		},
		{ // Test 1: aws kms.
			Name: "aws-kms",
			New:  kms.NewProvider,
			A:    "arn:aws:kms:us-east-1:111122223333:key/aaaa1234-ef56-7890-abcd-ef1234567890",
			B:    "arn:aws:kms:us-east-1:111122223333:key/bbbb1234-ef56-7890-abcd-ef1234567890",
		},
		{ // Test 2: gcp kms.
			Name: "gcp-kms",
			New:  gcpkms.NewProvider,
			A:    "projects/p/locations/us/keyRings/r/cryptoKeys/a",
			B:    "projects/p/locations/us/keyRings/r/cryptoKeys/b",
		},
		{ // Test 3: vault.
			Name: "vault",
			New:  vault.NewProvider,
			A:    "https://vault.example.com/v1/transit/keys/a",
			B:    "https://vault.example.com/v1/transit/keys/b",
		},
		{ // Test 4: azure key vault.
			Name: "azure-keyvault",
			New:  azkv.NewProvider,
			A:    "https://kv.vault.azure.net/keys/a/abc",
			B:    "https://kv.vault.azure.net/keys/b/def",
		},
		{ // Test 5: pgp.
			Name: "pgp",
			New:  pgp.NewProvider,
			A:    "AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555",
			B:    "BBBB1111CCCC2222DDDD3333EEEE4444FFFF5555",
		},
	}
	for i, s := range samples {
		t.Run(s.Name, func(t *testing.T) {
			t.Parallel()
			kp, err := s.New(s.A, s.B)
			if err != nil {
				t.Fatalf("Test %d (%s): build: %v", i, s.Name, err)
			}
			groups, err := kp.KeyGroups(context.Background())
			if err != nil {
				t.Fatalf("Test %d (%s): KeyGroups: %v", i, s.Name, err)
			}
			if len(groups) != 1 {
				t.Errorf("Test %d (%s): groups = %d, want 1", i, s.Name, len(groups))
			}
			if len(groups) > 0 && len(groups[0]) != 2 {
				t.Errorf("Test %d (%s): keys in group = %d, want 2",
					i, s.Name, len(groups[0]))
			}
		})
	}
}
