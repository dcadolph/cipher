package cipher_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"filippo.io/age"
	"github.com/spf13/afero"

	"github.com/dcadolph/cipher"
	cipherage "github.com/dcadolph/cipher/age"
)

// TestEditRoundTrip verifies that Edit decrypts, applies fn, re-encrypts,
// and persists the result. A subsequent Decode recovers the modified value.
func TestEditRoundTrip(t *testing.T) {
	recipient := newAgeIdentity(t)
	enc := cipher.NewEncoder(cipherage.NewProvider(recipient))
	dec := cipher.NewDecoder()
	ctx := context.Background()

	files := afero.NewMemMapFs()
	encrypted, err := enc.Encode(ctx, "x.yaml", []byte("foo: bar\n"))
	if err != nil {
		t.Fatalf("setup encode: %v", err)
	}
	if err := afero.WriteFile(files, "x.yaml", encrypted, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	err = cipher.Edit(ctx, files, "x.yaml", enc, dec, func(b []byte) ([]byte, error) {
		return []byte(strings.Replace(string(b), "bar", "QUUX", 1)), nil
	})
	if err != nil {
		t.Fatalf("Edit: %v", err)
	}

	after, _ := afero.ReadFile(files, "x.yaml")
	if !cipher.IsEncryptedPath("x.yaml", after) {
		t.Fatalf("file should still be encrypted after Edit")
	}
	plain, err := dec.Decode(ctx, "x.yaml", after)
	if err != nil {
		t.Fatalf("decode after edit: %v", err)
	}
	if !strings.Contains(string(plain), "QUUX") {
		t.Errorf("Edit did not persist mutation, got %q", plain)
	}
}

// TestEditWithBackupSuffix verifies EditWith preserves the original
// encrypted file at <path><suffix> after a mutation.
func TestEditWithBackupSuffix(t *testing.T) {
	recipient := newAgeIdentity(t)
	enc := cipher.NewEncoder(cipherage.NewProvider(recipient))
	dec := cipher.NewDecoder()
	ctx := context.Background()

	files := afero.NewMemMapFs()
	encrypted, _ := enc.Encode(ctx, "x.yaml", []byte("foo: bar\n"))
	if err := afero.WriteFile(files, "x.yaml", encrypted, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	err := cipher.EditWith(ctx, files, "x.yaml", enc, dec,
		func(b []byte) ([]byte, error) { return append(b, []byte("baz: qux\n")...), nil },
		cipher.EditOptions{BackupSuffix: ".bak"},
	)
	if err != nil {
		t.Fatalf("EditWith: %v", err)
	}
	backup, err := afero.ReadFile(files, "x.yaml.bak")
	if err != nil {
		t.Fatalf("read backup: %v", err)
	}
	if string(backup) != string(encrypted) {
		t.Errorf("backup mismatch")
	}
}

// TestEditNoChangeSkipsWrite verifies that returning the same bytes
// from fn results in no on-disk change.
func TestEditNoChangeSkipsWrite(t *testing.T) {
	recipient := newAgeIdentity(t)
	enc := cipher.NewEncoder(cipherage.NewProvider(recipient))
	dec := cipher.NewDecoder()
	ctx := context.Background()

	files := afero.NewMemMapFs()
	encrypted, _ := enc.Encode(ctx, "x.yaml", []byte("foo: bar\n"))
	if err := afero.WriteFile(files, "x.yaml", encrypted, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	before, _ := afero.ReadFile(files, "x.yaml")

	err := cipher.Edit(ctx, files, "x.yaml", enc, dec, func(b []byte) ([]byte, error) {
		return b, nil
	})
	if err != nil {
		t.Fatalf("Edit: %v", err)
	}

	after, _ := afero.ReadFile(files, "x.yaml")
	if string(before) != string(after) {
		t.Errorf("Edit unexpectedly modified file when fn was a no-op")
	}
}

// TestEditErrorPreservesFile verifies that an error from fn leaves the
// file untouched.
func TestEditErrorPreservesFile(t *testing.T) {
	recipient := newAgeIdentity(t)
	enc := cipher.NewEncoder(cipherage.NewProvider(recipient))
	dec := cipher.NewDecoder()
	ctx := context.Background()

	files := afero.NewMemMapFs()
	encrypted, _ := enc.Encode(ctx, "x.yaml", []byte("foo: bar\n"))
	if err := afero.WriteFile(files, "x.yaml", encrypted, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	before, _ := afero.ReadFile(files, "x.yaml")

	boom := errors.New("boom")
	err := cipher.Edit(ctx, files, "x.yaml", enc, dec, func([]byte) ([]byte, error) {
		return nil, boom
	})
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want errors.Is boom", err)
	}
	after, _ := afero.ReadFile(files, "x.yaml")
	if string(before) != string(after) {
		t.Errorf("Edit modified file despite fn returning error")
	}
}

// TestRotateProducesDifferentCiphertextSamePlaintext verifies that Rotate
// changes the ciphertext while leaving plaintext recoverable.
func TestRotateProducesDifferentCiphertextSamePlaintext(t *testing.T) {
	recipient := newAgeIdentity(t)
	enc := cipher.NewEncoder(cipherage.NewProvider(recipient))
	dec := cipher.NewDecoder()
	ctx := context.Background()

	first, err := enc.Encode(ctx, "x.yaml", []byte("foo: bar\n"))
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	rotated, err := cipher.Rotate(ctx, "x.yaml", first, enc, dec)
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if string(first) == string(rotated) {
		t.Fatalf("Rotate should change ciphertext")
	}
	plain, err := dec.Decode(ctx, "x.yaml", rotated)
	if err != nil {
		t.Fatalf("decode rotated: %v", err)
	}
	if !strings.Contains(string(plain), "foo: bar") {
		t.Errorf("rotated plaintext does not contain original value")
	}
}

// TestRotateWalk verifies that RotateWalk rotates every matching file
// in place.
func TestRotateWalk(t *testing.T) {
	recipient := newAgeIdentity(t)
	enc := cipher.NewEncoder(cipherage.NewProvider(recipient))
	dec := cipher.NewDecoder()
	ctx := context.Background()

	files := afero.NewMemMapFs()
	for _, p := range []string{"root/a.yaml", "root/sub/b.yaml"} {
		c, _ := enc.Encode(ctx, p, []byte("foo: bar\n"))
		if err := afero.WriteFile(files, p, c, 0o600); err != nil {
			t.Fatalf("write %q: %v", p, err)
		}
	}
	before, _ := afero.ReadFile(files, "root/a.yaml")

	err := cipher.RotateWalk(ctx, files, "root", enc, dec, []cipher.FileMatcher{
		cipher.MatchExt("yaml"),
	})
	if err != nil {
		t.Fatalf("RotateWalk: %v", err)
	}
	after, _ := afero.ReadFile(files, "root/a.yaml")
	if string(before) == string(after) {
		t.Errorf("RotateWalk did not change %q", "root/a.yaml")
	}
}

// TestAddAndRemoveRecipient verifies that adding then removing a
// recipient preserves the decrypted plaintext and the ability of the
// original recipient to decrypt.
func TestAddAndRemoveRecipient(t *testing.T) {
	r1 := newAgeIdentity(t)
	enc1 := cipher.NewEncoder(cipherage.NewProvider(r1))
	dec := cipher.NewDecoder()
	ctx := context.Background()

	cipherText, err := enc1.Encode(ctx, "x.yaml", []byte("foo: bar\n"))
	if err != nil {
		t.Fatalf("encode: %v", err)
	}

	id2, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate id2: %v", err)
	}
	r2 := id2.Recipient().String()

	updated, err := cipher.AddRecipient(
		ctx, "x.yaml", cipherText,
		cipherage.NewProvider(r2),
		cipher.DecoderOptions{},
	)
	if err != nil {
		t.Fatalf("AddRecipient: %v", err)
	}

	// Original recipient (r1 in env) can still decrypt.
	plain, err := dec.Decode(ctx, "x.yaml", updated)
	if err != nil {
		t.Fatalf("decode after AddRecipient: %v", err)
	}
	if !strings.Contains(string(plain), "foo: bar") {
		t.Errorf("plaintext lost after AddRecipient: %q", plain)
	}

	// Remove r2 by its age recipient string.
	pruned, err := cipher.RemoveRecipient(ctx, "x.yaml", updated, r2)
	if err != nil {
		t.Fatalf("RemoveRecipient: %v", err)
	}
	plain2, err := dec.Decode(ctx, "x.yaml", pruned)
	if err != nil {
		t.Fatalf("decode after RemoveRecipient: %v", err)
	}
	if !strings.Contains(string(plain2), "foo: bar") {
		t.Errorf("plaintext lost after RemoveRecipient: %q", plain2)
	}
}

// TestRemoveRecipientUnknownIdentifier verifies that asking to remove
// an unknown identifier returns an error rather than silently no-op'ing.
func TestRemoveRecipientUnknownIdentifier(t *testing.T) {
	recipient := newAgeIdentity(t)
	enc := cipher.NewEncoder(cipherage.NewProvider(recipient))
	ctx := context.Background()

	ct, _ := enc.Encode(ctx, "x.yaml", []byte("foo: bar\n"))
	_, err := cipher.RemoveRecipient(ctx, "x.yaml", ct, "age1nonexistent")
	if err == nil {
		t.Fatal("expected error for unknown identifier")
	}
}

// TestAddRecipientOnPlaintext verifies that AddRecipient refuses to
// operate on non-encrypted input.
func TestAddRecipientOnPlaintext(t *testing.T) {
	t.Parallel()
	_, err := cipher.AddRecipient(
		context.Background(), "x.yaml", []byte("foo: bar\n"),
		cipher.StaticKeyProvider(),
		cipher.DecoderOptions{},
	)
	// Either ErrNotEncrypted or an empty-groups failure is acceptable.
	if err == nil {
		t.Fatal("expected error on plaintext input")
	}
}
