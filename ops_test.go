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
	enc := cipher.NewEncoder(cipherage.MustNewProvider(recipient))
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
	enc := cipher.NewEncoder(cipherage.MustNewProvider(recipient))
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
	enc := cipher.NewEncoder(cipherage.MustNewProvider(recipient))
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
	enc := cipher.NewEncoder(cipherage.MustNewProvider(recipient))
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
	enc := cipher.NewEncoder(cipherage.MustNewProvider(recipient))
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
	enc := cipher.NewEncoder(cipherage.MustNewProvider(recipient))
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
	enc1 := cipher.NewEncoder(cipherage.MustNewProvider(r1))
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
		cipherage.MustNewProvider(r2),
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
	pruned, err := cipher.RemoveRecipient("x.yaml", updated, r2)
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
	enc := cipher.NewEncoder(cipherage.MustNewProvider(recipient))
	ctx := context.Background()

	ct, _ := enc.Encode(ctx, "x.yaml", []byte("foo: bar\n"))
	_, err := cipher.RemoveRecipient("x.yaml", ct, "age1nonexistent")
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

// TestAddRecipientEmptyProviderReturnsNoKeyGroups verifies parity with
// Encoder: a provider that yields zero key groups produces
// ErrNoKeyGroups rather than silently calling sopsx.AddRecipient with
// an empty NewGroups slice. Does not call t.Parallel because
// newAgeIdentity uses t.Setenv.
func TestAddRecipientEmptyProviderReturnsNoKeyGroups(t *testing.T) {
	recipient := newAgeIdentity(t)
	enc := cipher.NewEncoder(cipherage.MustNewProvider(recipient))
	ctx := context.Background()
	ct, err := enc.Encode(ctx, "x.yaml", []byte("foo: bar\n"))
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	_, err = cipher.AddRecipient(
		ctx, "x.yaml", ct,
		cipher.StaticKeyProvider(),
		cipher.DecoderOptions{},
	)
	if !errors.Is(err, cipher.ErrNoKeyGroups) {
		t.Fatalf("err = %v, want errors.Is ErrNoKeyGroups", err)
	}
}

// TestRemoveRecipientRefusesOrphan verifies that removing the last
// recipient from a file returns ErrOrphanRecipient by default.
func TestRemoveRecipientRefusesOrphan(t *testing.T) {
	recipient := newAgeIdentity(t)
	enc := cipher.NewEncoder(cipherage.MustNewProvider(recipient))
	ctx := context.Background()

	ct, err := enc.Encode(ctx, "x.yaml", []byte("foo: bar\n"))
	if err != nil {
		t.Fatalf("encode: %v", err)
	}

	_, err = cipher.RemoveRecipient("x.yaml", ct, recipient)
	if !errors.Is(err, cipher.ErrOrphanRecipient) {
		t.Fatalf("err = %v, want errors.Is ErrOrphanRecipient", err)
	}
}

// TestRemoveRecipientWithAllowOrphan verifies that AllowOrphan permits
// removing the final recipient. The resulting payload is no longer
// decryptable, but the operation itself succeeds.
func TestRemoveRecipientWithAllowOrphan(t *testing.T) {
	recipient := newAgeIdentity(t)
	enc := cipher.NewEncoder(cipherage.MustNewProvider(recipient))
	ctx := context.Background()

	ct, err := enc.Encode(ctx, "x.yaml", []byte("foo: bar\n"))
	if err != nil {
		t.Fatalf("encode: %v", err)
	}

	out, err := cipher.RemoveRecipientWith(
		"x.yaml", ct, []string{recipient},
		cipher.RemoveRecipientOptions{AllowOrphan: true},
	)
	if err != nil {
		t.Fatalf("RemoveRecipientWith: %v", err)
	}
	if len(out) == 0 {
		t.Fatal("RemoveRecipientWith produced empty output")
	}
}

// TestDecoderMaxCiphertextBytes verifies that Decoder returns ErrTooLarge
// when the input exceeds the configured cap.
func TestDecoderMaxCiphertextBytes(t *testing.T) {
	recipient := newAgeIdentity(t)
	enc := cipher.NewEncoder(cipherage.MustNewProvider(recipient))
	dec := cipher.NewDecoderWith(cipher.DecoderOptions{MaxCiphertextBytes: 16})
	ctx := context.Background()

	ct, err := enc.Encode(ctx, "x.yaml", []byte("foo: bar\n"))
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if len(ct) <= 16 {
		t.Fatalf("test setup: encoded ciphertext is %d bytes, expected >16", len(ct))
	}
	_, err = dec.Decode(ctx, "x.yaml", ct)
	if !errors.Is(err, cipher.ErrTooLarge) {
		t.Fatalf("err = %v, want errors.Is ErrTooLarge", err)
	}
}

// TestRemoveRecipientMaxCiphertextBytes verifies the cap is honored on
// the RemoveRecipient code path.
func TestRemoveRecipientMaxCiphertextBytes(t *testing.T) {
	recipient := newAgeIdentity(t)
	enc := cipher.NewEncoder(cipherage.MustNewProvider(recipient))
	ctx := context.Background()

	ct, err := enc.Encode(ctx, "x.yaml", []byte("foo: bar\n"))
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	_, err = cipher.RemoveRecipientWith(
		"x.yaml", ct, []string{recipient},
		cipher.RemoveRecipientOptions{MaxCiphertextBytes: 16},
	)
	if !errors.Is(err, cipher.ErrTooLarge) {
		t.Fatalf("err = %v, want errors.Is ErrTooLarge", err)
	}
}

// TestAddRecipientWithAsGroups verifies that AsGroups mode appends new
// key groups rather than flattening into the first one. The decryption
// path is not exercised here because adding a key group with default
// Shamir defaults raises the threshold; that interaction belongs in a
// separate test.
func TestAddRecipientWithAsGroups(t *testing.T) {
	r1 := newAgeIdentity(t)
	enc1 := cipher.NewEncoder(cipherage.MustNewProvider(r1))
	ctx := context.Background()

	ct, err := enc1.Encode(ctx, "x.yaml", []byte("foo: bar\n"))
	if err != nil {
		t.Fatalf("encode: %v", err)
	}

	id2, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate id2: %v", err)
	}
	r2 := id2.Recipient().String()

	updated, err := cipher.AddRecipientWith(
		ctx, "x.yaml", ct, cipherage.MustNewProvider(r2),
		cipher.AddRecipientOptions{Mode: cipher.AddRecipientAsGroups},
	)
	if err != nil {
		t.Fatalf("AddRecipientWith: %v", err)
	}

	info, err := cipher.InspectPath("x.yaml", updated)
	if err != nil {
		t.Fatalf("InspectPath: %v", err)
	}
	if len(info.Groups) < 2 {
		t.Errorf("AsGroups did not append a new group: groups=%d", len(info.Groups))
	}
}
