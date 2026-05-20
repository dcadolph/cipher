package age_test

import (
	"context"
	"testing"

	filippoage "filippo.io/age"

	cipherage "github.com/dcadolph/cipher/age"
)

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
		_ = cipherage.NewProvider()
	})

	t.Run("only whitespace", func(t *testing.T) {
		t.Parallel()
		defer func() {
			if r := recover(); r == nil {
				t.Fatal("expected panic when all recipients are blank")
			}
		}()
		_ = cipherage.NewProvider("   ", "")
	})
}

// TestKeyGroupsSingleGroupPerProvider verifies a Provider produces one
// key group containing one master key per recipient.
func TestKeyGroupsSingleGroupPerProvider(t *testing.T) {
	t.Parallel()
	r1, r2 := freshRecipient(t), freshRecipient(t)
	kp := cipherage.NewProvider(r1, r2)
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

// TestNewProviderFromCSV verifies parsing of a comma-separated list.
func TestNewProviderFromCSV(t *testing.T) {
	t.Parallel()
	r1, r2 := freshRecipient(t), freshRecipient(t)
	kp := cipherage.NewProviderFromCSV(r1 + ", " + r2)
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
