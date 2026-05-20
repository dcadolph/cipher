package cipher_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"filippo.io/age"

	"github.com/dcadolph/cipher"
	cipherage "github.com/dcadolph/cipher/age"
)

// TestInspectPopulatesMetadata verifies that Inspect surfaces the
// recipients, MAC, and version from a freshly encrypted file.
func TestInspectPopulatesMetadata(t *testing.T) {
	recipient := newAgeIdentity(t)
	enc := cipher.NewEncoder(cipherage.NewProvider(recipient))
	ct, err := enc.Encode(context.Background(), "x.yaml", []byte("foo: bar\n"))
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	info, err := cipher.InspectPath("x.yaml", ct)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if info.MAC == "" {
		t.Errorf("MAC empty")
	}
	if info.Version == "" {
		t.Errorf("Version empty")
	}
	if len(info.Groups) != 1 || len(info.Groups[0]) != 1 {
		t.Fatalf("groups shape = %v, want one group of one recipient", info.Groups)
	}
	if info.Groups[0][0].Identifier != recipient {
		t.Errorf("recipient = %q, want %q", info.Groups[0][0].Identifier, recipient)
	}
	if info.Groups[0][0].Type != "age" {
		t.Errorf("type = %q, want \"age\"", info.Groups[0][0].Type)
	}
}

// TestInspectRejectsPlaintext verifies the not-encrypted error.
func TestInspectRejectsPlaintext(t *testing.T) {
	t.Parallel()
	_, err := cipher.Inspect([]byte("foo: bar\n"), cipher.FormatYAML)
	if !errors.Is(err, cipher.ErrNotEncrypted) {
		t.Errorf("err = %v, want errors.Is ErrNotEncrypted", err)
	}
}

// TestDiffRecipientsAddRemove verifies that the diff reports the right
// additions and removals across two encrypted versions of the same
// secret.
func TestDiffRecipientsAddRemove(t *testing.T) {
	r1 := newAgeIdentity(t)
	id2, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	r2 := id2.Recipient().String()

	enc1 := cipher.NewEncoder(cipherage.NewProvider(r1))
	before, err := enc1.Encode(context.Background(), "x.yaml", []byte("foo: bar\n"))
	if err != nil {
		t.Fatalf("encode before: %v", err)
	}
	after, err := cipher.AddRecipient(
		context.Background(), "x.yaml", before,
		cipherage.NewProvider(r2), cipher.DecoderOptions{},
	)
	if err != nil {
		t.Fatalf("AddRecipient: %v", err)
	}

	diff, err := cipher.DiffRecipientsPath("x.yaml", before, after)
	if err != nil {
		t.Fatalf("DiffRecipientsPath: %v", err)
	}
	if len(diff.Added) != 1 || !strings.HasSuffix(diff.Added[0], r2) {
		t.Errorf("Added = %v, want one entry ending in %q", diff.Added, r2)
	}
	if len(diff.Removed) != 0 {
		t.Errorf("Removed = %v, want empty", diff.Removed)
	}

	// Reverse direction: original recipient becomes "removed."
	reverse, err := cipher.DiffRecipientsPath("x.yaml", after, before)
	if err != nil {
		t.Fatalf("DiffRecipientsPath reverse: %v", err)
	}
	if len(reverse.Removed) != 1 || !strings.HasSuffix(reverse.Removed[0], r2) {
		t.Errorf("reverse Removed = %v, want one entry ending in %q", reverse.Removed, r2)
	}
}

// TestDiffRecipientsEmpty verifies Empty reports correctly for an
// unchanged comparison.
func TestDiffRecipientsEmpty(t *testing.T) {
	recipient := newAgeIdentity(t)
	enc := cipher.NewEncoder(cipherage.NewProvider(recipient))
	ct, err := enc.Encode(context.Background(), "x.yaml", []byte("foo: bar\n"))
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	diff, err := cipher.DiffRecipientsPath("x.yaml", ct, ct)
	if err != nil {
		t.Fatalf("DiffRecipientsPath: %v", err)
	}
	if !diff.Empty() {
		t.Errorf("expected empty diff, got added=%v removed=%v", diff.Added, diff.Removed)
	}
}
