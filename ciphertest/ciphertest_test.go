package ciphertest_test

import (
	"context"
	"os"
	"testing"

	"github.com/dcadolph/cipher"
	"github.com/dcadolph/cipher/ciphertest"
)

// TestNewProviderRoundTrip verifies the helper produces a working
// recipient / identity pair end-to-end.
func TestNewProviderRoundTrip(t *testing.T) {
	kp, _ := ciphertest.NewProvider(t)
	enc := cipher.NewEncoder(kp)
	dec := cipher.NewDecoder()
	ciphertest.AssertRoundTrip(
		t, context.Background(), enc, dec,
		"x.yaml", []byte("foo: bar\n"), "foo: bar",
	)
}

// TestAssertRoundTripMultipleSubstrings exercises the contains-list path.
func TestAssertRoundTripMultipleSubstrings(t *testing.T) {
	kp, _ := ciphertest.NewProvider(t)
	enc := cipher.NewEncoder(kp)
	dec := cipher.NewDecoder()
	ciphertest.AssertRoundTrip(
		t, context.Background(), enc, dec,
		"creds.json", []byte(`{"user":"alice","pass":"hunter2"}`),
		`"user"`, `"alice"`, `"pass"`, `"hunter2"`,
	)
}

// TestNewAgeIdentityRegistersEnv verifies the helper registers
// SOPS_AGE_KEY so a default Decoder can decrypt the produced
// recipient's ciphertext.
func TestNewAgeIdentityRegistersEnv(t *testing.T) {
	recipient := ciphertest.NewAgeIdentity(t)
	if recipient == "" {
		t.Fatal("recipient is empty")
	}
	if got := os.Getenv("SOPS_AGE_KEY"); got == "" {
		t.Fatal("SOPS_AGE_KEY not set after NewAgeIdentity")
	}
}

// TestMustAgeProviderConstructs verifies the helper builds a provider
// from a recipient created via NewAgeIdentity and that the provider
// produces exactly one key group.
func TestMustAgeProviderConstructs(t *testing.T) {
	recipient := ciphertest.NewAgeIdentity(t)
	kp := ciphertest.MustAgeProvider(t, recipient)
	groups, err := kp.KeyGroups(context.Background())
	if err != nil {
		t.Fatalf("KeyGroups: %v", err)
	}
	if len(groups) != 1 {
		t.Fatalf("groups = %d, want 1", len(groups))
	}
	if len(groups[0]) != 1 {
		t.Fatalf("group size = %d, want 1", len(groups[0]))
	}
}
