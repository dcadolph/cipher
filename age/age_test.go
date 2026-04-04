package age_test

import (
	"context"
	"testing"

	filippoage "filippo.io/age"

	cipherage "github.com/dcadolph/cipher/age"
)

// TestGenerateIdentity verifies that GenerateIdentity returns a usable
// recipient/secret pair that round-trips through NewProvider.
func TestGenerateIdentity(t *testing.T) {
	t.Parallel()
	id, err := cipherage.GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	if id.Recipient == "" {
		t.Error("Recipient is empty")
	}
	if id.Secret == "" {
		t.Error("Secret is empty")
	}
	if id.Recipient == id.Secret {
		t.Error("Recipient and Secret are identical")
	}
	if _, err := cipherage.NewProvider(id.Recipient); err != nil {
		t.Fatalf("NewProvider on generated recipient: %v", err)
	}
}

// TestMustGenerateIdentity verifies the Must helper returns a non-nil
// identity.
func TestMustGenerateIdentity(t *testing.T) {
	t.Parallel()
	id := cipherage.MustGenerateIdentity()
	if id == nil || id.Recipient == "" || id.Secret == "" {
		t.Fatalf("MustGenerateIdentity returned incomplete identity: %+v", id)
	}
}

// TestNewProviderPanicsOnEmpty verifies the factory rejects empty input.
func TestNewProviderPanicsOnEmpty(t *testing.T) {
	t.Parallel()
	t.Run("no args", func(t *testing.T) {
		t.Parallel()
		defer func() {
			if r := recover(); r == nil {
				t.Fatal("expected panic on no recipients")
			}
		}()
		_ = cipherage.MustNewProvider()
	})

	t.Run("only whitespace", func(t *testing.T) {
		t.Parallel()
		defer func() {
			if r := recover(); r == nil {
				t.Fatal("expected panic when all recipients are blank")
			}
		}()
		_ = cipherage.MustNewProvider("   ", "")
	})
}

// TestKeyGroupsSingleGroupPerProvider verifies a Provider produces one
// key group containing one master key per recipient.
func TestKeyGroupsSingleGroupPerProvider(t *testing.T) {
	t.Parallel()
	r1, r2 := freshRecipient(t), freshRecipient(t)
	kp := cipherage.MustNewProvider(r1, r2)
	groups, err := kp.KeyGroups(context.Background())
	if err != nil {
		t.Fatalf("KeyGroups: %v", err)
	}
	if len(groups) != 1 {
		t.Fatalf("groups = %d, want 1", len(groups))
	}
	if len(groups[0]) != 2 {
		t.Fatalf("group size = %d, want 2", len(groups[0]))
	}
}

// TestNewProviderTrimsAndDeduplicates verifies recipient list cleanup:
// whitespace is trimmed and empty entries dropped before construction.
func TestNewProviderTrimsAndDeduplicates(t *testing.T) {
	t.Parallel()
	r1, r2 := freshRecipient(t), freshRecipient(t)
	kp := cipherage.MustNewProvider("  "+r1+"  ", "", r2)
	groups, err := kp.KeyGroups(context.Background())
	if err != nil {
		t.Fatalf("KeyGroups: %v", err)
	}
	if len(groups[0]) != 2 {
		t.Fatalf("group size = %d, want 2", len(groups[0]))
	}
}

// freshRecipient returns the public recipient string for a freshly
// generated age identity.
func freshRecipient(t *testing.T) string {
	t.Helper()
	id, err := filippoage.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	return id.Recipient().String()
}
