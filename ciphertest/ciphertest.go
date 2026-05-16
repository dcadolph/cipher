// Package ciphertest provides test helpers for code that uses cipher.
//
// It hides the env-variable plumbing required for age round-trips and
// exposes a few short-form assertion helpers.
//
// # No parallel tests
//
// Tests using helpers that mutate the SOPS_AGE_KEY environment
// variable must not call t.Parallel. The helpers set the env via
// t.Setenv, which serializes access to process state. Parallel tests
// would race on the same env slot. The doc comment on each helper
// repeats this constraint.
//
// # Two helpers
//
//   - [NewAgeIdentity] generates a fresh age identity, registers
//     SOPS_AGE_KEY via t.Setenv, and returns the public recipient.
//   - [NewProvider] wraps NewAgeIdentity and returns a working
//     [cipher.KeyProvider]. The provider yields a single age recipient
//     whose private identity is already in the env.
//
// # AssertRoundTrip
//
// [AssertRoundTrip] encrypts via the supplied [cipher.Encoder],
// decrypts via the supplied [cipher.Decoder], and verifies the
// resulting plaintext contains each provided substring. Sops
// canonicalizes YAML on emit, so verifying full equality of bytes is
// brittle. Verifying substrings is the right interface for round-trip
// tests.
//
// # Quick start
//
//	func TestMyHandler(t *testing.T) {
//	    kp, _ := ciphertest.NewProvider(t)
//	    enc := cipher.NewEncoder(kp)
//	    dec := cipher.NewDecoder()
//	    ciphertest.AssertRoundTrip(t, context.Background(), enc, dec,
//	        "secrets.yaml", []byte("foo: bar\n"), "foo: bar")
//	}
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
// Fails the test if provider construction errors.
func NewProvider(t testing.TB) (kp cipher.KeyProvider, recipient string) {
	t.Helper()
	recipient = NewAgeIdentity(t)
	kp, err := cipherage.NewProvider(recipient)
	if err != nil {
		t.Fatalf("ciphertest: age.NewProvider: %v", err)
	}
	return kp, recipient
}

// MustAgeProvider returns an age cipher.KeyProvider for the supplied
// recipients and fails the test on construction error. Use in tests
// where the recipient list is statically known to be valid.
func MustAgeProvider(t testing.TB, recipients ...string) cipher.KeyProvider {
	t.Helper()
	kp, err := cipherage.NewProvider(recipients...)
	if err != nil {
		t.Fatalf("ciphertest: age.NewProvider: %v", err)
	}
	return kp
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
