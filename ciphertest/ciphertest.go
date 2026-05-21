// Package ciphertest provides test helpers for code that uses cipher.
// It hides the env-variable plumbing required for age round-trips and
// exposes a few short-form assertion helpers.
//
// Tests using helpers that mutate the SOPS_AGE_KEY environment
// variable must not run in parallel; the helpers below document this.
package ciphertest

import (
	"context"
	"strings"
	"testing"

	"filippo.io/age"

	"github.com/dcadolph/cipher"
	cipherage "github.com/dcadolph/cipher/age"
)

// NewAgeIdentity generates a fresh age identity, sets SOPS_AGE_KEY in
// the process environment so a default cipher.Decoder can decrypt files
// encrypted with the returned recipient, and returns the recipient
// string. The cleanup restores the original env after the test.
//
// Tests that call this helper must not invoke t.Parallel because
// SOPS_AGE_KEY is process-global.
func NewAgeIdentity(t testing.TB) (recipient string) {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("ciphertest: generate identity: %v", err)
	}
	switch tt := t.(type) {
	case *testing.T:
		tt.Setenv("SOPS_AGE_KEY", id.String())
	case *testing.B:
		tt.Setenv("SOPS_AGE_KEY", id.String())
	default:
		t.Fatalf("ciphertest: unsupported testing type %T", t)
	}
	return id.Recipient().String()
}

// NewProvider is a convenience that combines NewAgeIdentity with
// cipherage.NewProvider. The returned KeyProvider yields a single age
// recipient for which the decryption identity is already in the env.
func NewProvider(t testing.TB) (kp cipher.KeyProvider, recipient string) {
	t.Helper()
	recipient = NewAgeIdentity(t)
	return cipherage.NewProvider(recipient), recipient
}

// AssertRoundTrip encrypts plain via enc, decrypts via dec, and verifies
// the resulting plaintext contains every string in contains. Useful for
// formats where sops's canonical output differs from the input but the
// semantic value is preserved.
//
// AssertRoundTrip fails the test on any error or missing substring.
func AssertRoundTrip(
	t testing.TB, ctx context.Context,
	enc cipher.Encoder, dec cipher.Decoder,
	path string, plain []byte, contains ...string,
) {
	t.Helper()
	ct, err := enc.Encode(ctx, path, plain)
	if err != nil {
		t.Fatalf("ciphertest: encode %q: %v", path, err)
	}
	if !cipher.IsEncryptedPath(path, ct) {
		t.Fatalf("ciphertest: encrypted output is not detected as encrypted")
	}
	out, err := dec.Decode(ctx, path, ct)
	if err != nil {
		t.Fatalf("ciphertest: decode %q: %v", path, err)
	}
	for _, want := range contains {
		if !strings.Contains(string(out), want) {
			t.Errorf("ciphertest: round-tripped plaintext missing %q (got %q)",
				want, out)
		}
	}
}

// MemoryFiles is a small alias indicating "use an in-memory afero.Fs"
// in tests. Kept as a doc anchor; callers should pass afero.NewMemMapFs()
// directly. Provided to keep this package's surface intentional.
const MemoryFiles = "use afero.NewMemMapFs()"
