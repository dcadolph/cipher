package cipher_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"filippo.io/age"
	"github.com/getsops/sops/v3"
	sopsage "github.com/getsops/sops/v3/age"
	"github.com/google/go-cmp/cmp"
	"github.com/spf13/afero"

	"github.com/dcadolph/cipher"
	cipherage "github.com/dcadolph/cipher/age"
)

// newAge generates an age identity, sets SOPS_AGE_KEY for the test, and
// returns the recipient. Tests that call this cannot use t.Parallel.
func newAge(t *testing.T) string {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	t.Setenv("SOPS_AGE_KEY", id.String())
	return id.Recipient().String()
}

// ageGroup returns a single sops key group for the supplied recipient.
func ageGroup(t *testing.T, recipient string) []sops.KeyGroup {
	t.Helper()
	mks, err := sopsage.MasterKeysFromRecipients(recipient)
	if err != nil {
		t.Fatalf("master keys: %v", err)
	}
	group := sops.KeyGroup{}
	for _, mk := range mks {
		group = append(group, mk)
	}
	return []sops.KeyGroup{group}
}

// TestEncoderInputTooLarge verifies MaxPlaintextBytes is enforced.
func TestEncoderInputTooLarge(t *testing.T) {
	recipient := newAge(t)
	enc := cipher.NewEncoderWith(cipherage.MustNewProvider(recipient), cipher.EncoderOptions{
		MaxPlaintextBytes: 8,
	})
	_, err := enc.Encode(context.Background(), "x.yaml", []byte("foo: barbaz\n"))
	if !errors.Is(err, cipher.ErrInputTooLarge) {
		t.Fatalf("err = %v, want ErrInputTooLarge", err)
	}
	if !errors.Is(err, cipher.ErrEncode) {
		t.Errorf("err = %v, want wrap of ErrEncode", err)
	}
}

// TestEncoderOnEncryptCalled verifies the OnEncrypt callback fires.
func TestEncoderOnEncryptCalled(t *testing.T) {
	recipient := newAge(t)
	var called atomic.Int32
	enc := cipher.NewEncoderWith(cipherage.MustNewProvider(recipient), cipher.EncoderOptions{
		OnEncrypt: func(path string, plaintextBytes, ciphertextBytes int) {
			if plaintextBytes <= 0 || ciphertextBytes <= 0 {
				t.Errorf("byte counts not populated")
			}
			called.Add(1)
		},
	})
	if _, err := enc.Encode(context.Background(), "x.yaml", []byte("foo: bar\n")); err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if called.Load() != 1 {
		t.Errorf("OnEncrypt invocations = %d, want 1", called.Load())
	}
}

// TestDecoderOnDecryptCalled verifies the OnDecrypt callback fires.
func TestDecoderOnDecryptCalled(t *testing.T) {
	recipient := newAge(t)
	enc := cipher.NewEncoder(cipherage.MustNewProvider(recipient))
	encrypted, err := enc.Encode(context.Background(), "x.yaml", []byte("foo: bar\n"))
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	var called atomic.Int32
	dec := cipher.NewDecoderWith(cipher.DecoderOptions{
		OnDecrypt: func(path string, ciphertextBytes, plaintextBytes int) {
			if ciphertextBytes <= 0 || plaintextBytes <= 0 {
				t.Errorf("byte counts not populated")
			}
			called.Add(1)
		},
	})
	if _, err := dec.Decode(context.Background(), "x.yaml", encrypted); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if called.Load() != 1 {
		t.Errorf("OnDecrypt invocations = %d, want 1", called.Load())
	}
}

// TestDecoderOnDecryptAuditCalled verifies that OnDecryptAudit fires
// with the file's recorded recipients after a successful Decode.
func TestDecoderOnDecryptAuditCalled(t *testing.T) {
	recipient := newAge(t)
	enc := cipher.NewEncoder(cipherage.MustNewProvider(recipient))
	encrypted, err := enc.Encode(context.Background(), "x.yaml", []byte("foo: bar\n"))
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	var seen []cipher.RecipientInfo
	var seenErr error
	dec := cipher.NewDecoderWith(cipher.DecoderOptions{
		OnDecryptAudit: func(_ string, rs []cipher.RecipientInfo, err error) {
			seen = rs
			seenErr = err
		},
	})
	if _, err := dec.Decode(context.Background(), "x.yaml", encrypted); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if len(seen) == 0 {
		t.Fatal("OnDecryptAudit got no recipients")
	}
	found := false
	for _, r := range seen {
		if r.Identifier == recipient {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected recipient %q not present in audit list: %+v", recipient, seen)
	}
	if seenErr != nil {
		t.Errorf("audit inspectErr = %v, want nil on a clean file", seenErr)
	}
}

// TestEncoderNilProviderResult verifies an empty provider yields ErrNoKeyGroups.
func TestEncoderNilProviderResult(t *testing.T) {
	t.Parallel()
	empty := cipher.KeyProviderFunc(func(context.Context) ([]sops.KeyGroup, error) {
		return nil, nil
	})
	enc := cipher.NewEncoder(empty)
	_, err := enc.Encode(context.Background(), "x.yaml", []byte("a: 1\n"))
	if !errors.Is(err, cipher.ErrNoKeyGroups) {
		t.Errorf("err = %v, want ErrNoKeyGroups", err)
	}
}

// TestEncoderKeyProviderError propagates errors from KeyGroups.
func TestEncoderKeyProviderError(t *testing.T) {
	t.Parallel()
	sentinel := errors.New("provider blew up")
	bad := cipher.KeyProviderFunc(func(context.Context) ([]sops.KeyGroup, error) {
		return nil, sentinel
	})
	enc := cipher.NewEncoder(bad)
	_, err := enc.Encode(context.Background(), "x.yaml", []byte("a: 1\n"))
	if !errors.Is(err, cipher.ErrEncode) || !errors.Is(err, sentinel) {
		t.Errorf("err = %v, want wraps of ErrEncode and sentinel", err)
	}
}

// TestNewEncoderPanicsOnNilProvider verifies the constructor panics
// when its required dependency is nil.
func TestNewEncoderPanicsOnNilProvider(t *testing.T) {
	t.Parallel()
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic")
		}
	}()
	cipher.NewEncoder(nil)
}

// TestChainEncodersPanicsOnNilFirst verifies the constructor panics
// when the first encoder is nil.
func TestChainEncodersPanicsOnNilFirst(t *testing.T) {
	t.Parallel()
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic")
		}
	}()
	cipher.ChainEncoders(nil)
}

// TestChainDecodersPanicsOnNilFirst verifies the constructor panics
// when the first decoder is nil.
func TestChainDecodersPanicsOnNilFirst(t *testing.T) {
	t.Parallel()
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic")
		}
	}()
	cipher.ChainDecoders(nil)
}

// TestChainEncodersPropagatesErrors verifies the chain stops at the
// first failing encoder and returns its error.
func TestChainEncodersPropagatesErrors(t *testing.T) {
	t.Parallel()
	sentinel := errors.New("boom")
	ok := cipher.EncoderFunc(func(_ context.Context, _ string, d []byte) ([]byte, error) {
		return d, nil
	})
	bad := cipher.EncoderFunc(func(_ context.Context, _ string, _ []byte) ([]byte, error) {
		return nil, sentinel
	})
	chain := cipher.ChainEncoders(ok, bad)
	_, err := chain.Encode(context.Background(), "x", []byte("a"))
	if !errors.Is(err, sentinel) {
		t.Errorf("err = %v, want sentinel", err)
	}
}

// TestChainDecodersPropagatesErrors verifies the chain stops at the
// first failing decoder and returns its error.
func TestChainDecodersPropagatesErrors(t *testing.T) {
	t.Parallel()
	sentinel := errors.New("boom")
	ok := cipher.DecoderFunc(func(_ context.Context, _ string, d []byte) ([]byte, error) {
		return d, nil
	})
	bad := cipher.DecoderFunc(func(_ context.Context, _ string, _ []byte) ([]byte, error) {
		return nil, sentinel
	})
	chain := cipher.ChainDecoders(ok, bad)
	_, err := chain.Decode(context.Background(), "x", []byte("a"))
	if !errors.Is(err, sentinel) {
		t.Errorf("err = %v, want sentinel", err)
	}
}

// TestEditNoChangeNoWrite verifies that returning unchanged bytes from
// the edit function leaves the file untouched and Edit returns nil.
func TestEditNoChangeNoWrite(t *testing.T) {
	recipient := newAge(t)
	enc := cipher.NewEncoder(cipherage.MustNewProvider(recipient))
	dec := cipher.NewDecoder()
	ctx := context.Background()

	files := afero.NewMemMapFs()
	encrypted, err := enc.Encode(ctx, "secrets.yaml", []byte("foo: bar\n"))
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if err := afero.WriteFile(files, "/secrets.yaml", encrypted, 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}

	err = cipher.Edit(ctx, files, "/secrets.yaml", enc, dec,
		func(plain []byte) ([]byte, error) { return plain, nil })
	if err != nil {
		t.Errorf("Edit no-change: %v", err)
	}
	got, _ := afero.ReadFile(files, "/secrets.yaml")
	if diff := cmp.Diff(string(encrypted), string(got)); diff != "" {
		t.Errorf("file changed after no-op edit (-want +got):\n%s", diff)
	}
}

// TestEditPropagatesFnError verifies a mutator error aborts the write.
func TestEditPropagatesFnError(t *testing.T) {
	recipient := newAge(t)
	enc := cipher.NewEncoder(cipherage.MustNewProvider(recipient))
	dec := cipher.NewDecoder()
	ctx := context.Background()

	files := afero.NewMemMapFs()
	encrypted, err := enc.Encode(ctx, "secrets.yaml", []byte("foo: bar\n"))
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if err := afero.WriteFile(files, "/secrets.yaml", encrypted, 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}

	sentinel := errors.New("mutator failed")
	err = cipher.Edit(ctx, files, "/secrets.yaml", enc, dec,
		func([]byte) ([]byte, error) { return nil, sentinel })
	if !errors.Is(err, sentinel) {
		t.Errorf("err = %v, want sentinel", err)
	}
	got, _ := afero.ReadFile(files, "/secrets.yaml")
	if string(got) != string(encrypted) {
		t.Errorf("file modified despite mutator failure")
	}
}

// TestEditWithBackup verifies BackupSuffix writes a sibling copy of the
// original before overwriting.
func TestEditWithBackup(t *testing.T) {
	recipient := newAge(t)
	enc := cipher.NewEncoder(cipherage.MustNewProvider(recipient))
	dec := cipher.NewDecoder()
	ctx := context.Background()

	files := afero.NewMemMapFs()
	encrypted, err := enc.Encode(ctx, "secrets.yaml", []byte("foo: bar\n"))
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if err := afero.WriteFile(files, "/secrets.yaml", encrypted, 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}

	err = cipher.EditWith(ctx, files, "/secrets.yaml", enc, dec,
		func(plain []byte) ([]byte, error) {
			return append(plain, []byte("extra: 1\n")...), nil
		}, cipher.EditOptions{BackupSuffix: ".bak"})
	if err != nil {
		t.Fatalf("EditWith: %v", err)
	}

	backup, err := afero.ReadFile(files, "/secrets.yaml.bak")
	if err != nil {
		t.Fatalf("read backup: %v", err)
	}
	if string(backup) != string(encrypted) {
		t.Errorf("backup did not preserve original")
	}
}

// TestEditPanicsOnNilArgs verifies each required arg triggers a panic.
func TestEditPanicsOnNilArgs(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	noopEnc := cipher.EncoderFunc(func(context.Context, string, []byte) ([]byte, error) { return nil, nil })
	noopDec := cipher.DecoderFunc(func(context.Context, string, []byte) ([]byte, error) { return nil, nil })
	noopFn := func([]byte) ([]byte, error) { return nil, nil }
	files := afero.NewMemMapFs()
	cases := []struct {
		Name string
		Run  func()
	}{
		{"nil files", func() { _ = cipher.Edit(ctx, nil, "x", noopEnc, noopDec, noopFn) }},
		{"nil enc", func() { _ = cipher.Edit(ctx, files, "x", nil, noopDec, noopFn) }},
		{"nil dec", func() { _ = cipher.Edit(ctx, files, "x", noopEnc, nil, noopFn) }},
		{"nil fn", func() { _ = cipher.Edit(ctx, files, "x", noopEnc, noopDec, nil) }},
	}
	for _, c := range cases {
		t.Run(c.Name, func(t *testing.T) {
			defer func() {
				if r := recover(); r == nil {
					t.Errorf("%s: expected panic", c.Name)
				}
			}()
			c.Run()
		})
	}
}

// TestRotatePanicsOnNilArgs verifies each required arg triggers a panic.
func TestRotatePanicsOnNilArgs(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	noopEnc := cipher.EncoderFunc(func(context.Context, string, []byte) ([]byte, error) { return nil, nil })
	noopDec := cipher.DecoderFunc(func(context.Context, string, []byte) ([]byte, error) { return nil, nil })
	cases := []struct {
		Name string
		Run  func()
	}{
		{"nil enc", func() { _, _ = cipher.Rotate(ctx, "x", []byte("y"), nil, noopDec) }},
		{"nil dec", func() { _, _ = cipher.Rotate(ctx, "x", []byte("y"), noopEnc, nil) }},
	}
	for _, c := range cases {
		t.Run(c.Name, func(t *testing.T) {
			defer func() {
				if r := recover(); r == nil {
					t.Errorf("%s: expected panic", c.Name)
				}
			}()
			c.Run()
		})
	}
}

// TestRotateDecodeError propagates the decoder error and wraps it.
func TestRotateDecodeError(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	enc := cipher.EncoderFunc(func(_ context.Context, _ string, d []byte) ([]byte, error) {
		return d, nil
	})
	sentinel := errors.New("decode failed")
	dec := cipher.DecoderFunc(func(context.Context, string, []byte) ([]byte, error) {
		return nil, sentinel
	})
	_, err := cipher.Rotate(ctx, "x.yaml", []byte("y"), enc, dec)
	if !errors.Is(err, sentinel) {
		t.Errorf("err = %v, want sentinel", err)
	}
}

// TestRemoveRecipientNoIdentifiers verifies the early-return error.
func TestRemoveRecipientNoIdentifiers(t *testing.T) {
	t.Parallel()
	_, err := cipher.RemoveRecipient("x.yaml", []byte("data"))
	if err == nil || !strings.Contains(err.Error(), "at least one") {
		t.Errorf("err = %v, want missing-identifier error", err)
	}
}

// TestRemoveRecipientNotEncrypted verifies the sentinel passthrough.
func TestRemoveRecipientNotEncrypted(t *testing.T) {
	t.Parallel()
	_, err := cipher.RemoveRecipient("x.yaml", []byte("foo: bar\n"), "age1x")
	if !errors.Is(err, cipher.ErrNotEncrypted) {
		t.Errorf("err = %v, want ErrNotEncrypted", err)
	}
}

// TestAddRecipientNotEncrypted verifies the sentinel passthrough.
func TestAddRecipientNotEncrypted(t *testing.T) {
	t.Parallel()
	provider := cipher.StaticKeyProvider(sops.KeyGroup{})
	_, err := cipher.AddRecipient(
		context.Background(), "x.yaml", []byte("foo: bar\n"),
		provider, cipher.DecoderOptions{},
	)
	if !errors.Is(err, cipher.ErrNotEncrypted) {
		t.Errorf("err = %v, want ErrNotEncrypted", err)
	}
}

// TestAddRecipientPanicsOnNilProvider verifies the constructor panic.
func TestAddRecipientPanicsOnNilProvider(t *testing.T) {
	t.Parallel()
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic")
		}
	}()
	_, _ = cipher.AddRecipient(context.Background(), "x.yaml", []byte{}, nil, cipher.DecoderOptions{})
}

// TestAddRecipientPropagatesProviderError verifies provider failures
// bubble up wrapped.
func TestAddRecipientPropagatesProviderError(t *testing.T) {
	t.Parallel()
	sentinel := errors.New("provider failed")
	provider := cipher.KeyProviderFunc(func(context.Context) ([]sops.KeyGroup, error) {
		return nil, sentinel
	})
	_, err := cipher.AddRecipient(
		context.Background(), "x.yaml", []byte("data"),
		provider, cipher.DecoderOptions{},
	)
	if !errors.Is(err, sentinel) {
		t.Errorf("err = %v, want sentinel", err)
	}
}

// TestRotateWalkSkipsPlain verifies plain files are skipped (not failed)
// in a rotate walk and OnSkip is called.
func TestRotateWalkSkipsPlain(t *testing.T) {
	recipient := newAge(t)
	enc := cipher.NewEncoder(cipherage.MustNewProvider(recipient))
	dec := cipher.NewDecoder()
	ctx := context.Background()

	files := afero.NewMemMapFs()
	if err := afero.WriteFile(files, "/root/plain.yaml", []byte("foo: bar\n"), 0o600); err != nil {
		t.Fatalf("seed plain: %v", err)
	}
	encrypted, err := enc.Encode(ctx, "/root/enc.yaml", []byte("foo: bar\n"))
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if err := afero.WriteFile(files, "/root/enc.yaml", encrypted, 0o600); err != nil {
		t.Fatalf("seed enc: %v", err)
	}

	var skipped, rotated int
	err = cipher.RotateWalkWith(ctx, files, "/root", enc, dec, nil, cipher.WalkOptions{
		OnFile: func(string, int) { rotated++ },
		OnSkip: func(string, error) { skipped++ },
	})
	if err != nil {
		t.Fatalf("RotateWalkWith: %v", err)
	}
	if skipped != 1 || rotated != 1 {
		t.Errorf("skipped=%d rotated=%d, want 1/1", skipped, rotated)
	}
}

// TestRotateWalkPanicsOnNilArgs verifies panics on required deps.
func TestRotateWalkPanicsOnNilArgs(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	files := afero.NewMemMapFs()
	noopEnc := cipher.EncoderFunc(func(context.Context, string, []byte) ([]byte, error) { return nil, nil })
	noopDec := cipher.DecoderFunc(func(context.Context, string, []byte) ([]byte, error) { return nil, nil })
	cases := []struct {
		Name string
		Run  func()
	}{
		{"nil files", func() { _ = cipher.RotateWalkWith(ctx, nil, "/", noopEnc, noopDec, nil, cipher.WalkOptions{}) }},
		{"nil enc", func() { _ = cipher.RotateWalkWith(ctx, files, "/", nil, noopDec, nil, cipher.WalkOptions{}) }},
		{"nil dec", func() { _ = cipher.RotateWalkWith(ctx, files, "/", noopEnc, nil, nil, cipher.WalkOptions{}) }},
	}
	for _, c := range cases {
		t.Run(c.Name, func(t *testing.T) {
			defer func() {
				if r := recover(); r == nil {
					t.Errorf("%s: expected panic", c.Name)
				}
			}()
			c.Run()
		})
	}
}

// TestEncodeWalkPanicsOnNilArgs verifies panics on required deps.
func TestEncodeWalkPanicsOnNilArgs(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	files := afero.NewMemMapFs()
	noopEnc := cipher.EncoderFunc(func(context.Context, string, []byte) ([]byte, error) { return nil, nil })
	cases := []struct {
		Name string
		Run  func()
	}{
		{"nil files", func() { _ = cipher.EncodeWalkWith(ctx, nil, "/", noopEnc, nil, cipher.WalkOptions{}) }},
		{"nil enc", func() { _ = cipher.EncodeWalkWith(ctx, files, "/", nil, nil, cipher.WalkOptions{}) }},
	}
	for _, c := range cases {
		t.Run(c.Name, func(t *testing.T) {
			defer func() {
				if r := recover(); r == nil {
					t.Errorf("%s: expected panic", c.Name)
				}
			}()
			c.Run()
		})
	}
}

// TestDecodeWalkPanicsOnNilArgs verifies panics on required deps.
func TestDecodeWalkPanicsOnNilArgs(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	files := afero.NewMemMapFs()
	noopDec := cipher.DecoderFunc(func(context.Context, string, []byte) ([]byte, error) { return nil, nil })
	cases := []struct {
		Name string
		Run  func()
	}{
		{"nil files", func() { _ = cipher.DecodeWalkWith(ctx, nil, "/", noopDec, nil, cipher.WalkOptions{}) }},
		{"nil dec", func() { _ = cipher.DecodeWalkWith(ctx, files, "/", nil, nil, cipher.WalkOptions{}) }},
	}
	for _, c := range cases {
		t.Run(c.Name, func(t *testing.T) {
			defer func() {
				if r := recover(); r == nil {
					t.Errorf("%s: expected panic", c.Name)
				}
			}()
			c.Run()
		})
	}
}

// TestEncodeWalkParallelMany exercises the parallel runWalk path with a
// non-trivial worker count and many files.
func TestEncodeWalkParallelMany(t *testing.T) {
	recipient := newAge(t)
	enc := cipher.NewEncoder(cipherage.MustNewProvider(recipient))
	ctx := context.Background()

	files := afero.NewMemMapFs()
	for i := 0; i < 16; i++ {
		path := filepath.Join("/root", "f"+itoa(i)+".yaml")
		if err := afero.WriteFile(files, path, []byte("foo: bar\n"), 0o600); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}

	var processed atomic.Int32
	err := cipher.EncodeWalkWith(ctx, files, "/root", enc, nil, cipher.WalkOptions{
		Parallelism: 4,
		OnFile:      func(string, int) { processed.Add(1) },
	})
	if err != nil {
		t.Fatalf("EncodeWalkWith: %v", err)
	}
	if processed.Load() != 16 {
		t.Errorf("processed = %d, want 16", processed.Load())
	}
}

// TestEncodeWalkParallelCancelOnError verifies the parallel walker
// cancels remaining work after the first error.
func TestEncodeWalkParallelCancelOnError(t *testing.T) {
	t.Parallel()
	files := afero.NewMemMapFs()
	for i := 0; i < 8; i++ {
		path := filepath.Join("/root", "f"+itoa(i)+".yaml")
		if err := afero.WriteFile(files, path, []byte("foo: bar\n"), 0o600); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}

	sentinel := errors.New("forced encode failure")
	enc := cipher.EncoderFunc(func(context.Context, string, []byte) ([]byte, error) {
		return nil, sentinel
	})
	err := cipher.EncodeWalkWith(context.Background(), files, "/root", enc, nil,
		cipher.WalkOptions{Parallelism: 4})
	if !errors.Is(err, sentinel) {
		t.Errorf("err = %v, want sentinel", err)
	}
}

// TestEncodeWalkContextCancel verifies an already-canceled context is
// honored by the walker.
func TestEncodeWalkContextCancel(t *testing.T) {
	t.Parallel()
	files := afero.NewMemMapFs()
	for i := 0; i < 4; i++ {
		path := filepath.Join("/root", "f"+itoa(i)+".yaml")
		if err := afero.WriteFile(files, path, []byte("foo: bar\n"), 0o600); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}

	enc := cipher.EncoderFunc(func(context.Context, string, []byte) ([]byte, error) {
		return []byte("encrypted"), nil
	})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := cipher.EncodeWalkWith(ctx, files, "/root", enc, nil, cipher.WalkOptions{})
	if !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled", err)
	}
}

// TestEncodeWalkBackupOnEncode verifies backups are written before
// in-place updates.
func TestEncodeWalkBackupOnEncode(t *testing.T) {
	recipient := newAge(t)
	enc := cipher.NewEncoder(cipherage.MustNewProvider(recipient))
	ctx := context.Background()
	files := afero.NewMemMapFs()
	original := []byte("foo: bar\n")
	if err := afero.WriteFile(files, "/root/a.yaml", original, 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	err := cipher.EncodeWalkWith(ctx, files, "/root", enc, nil,
		cipher.WalkOptions{BackupSuffix: ".bak"})
	if err != nil {
		t.Fatalf("EncodeWalkWith: %v", err)
	}
	backup, err := afero.ReadFile(files, "/root/a.yaml.bak")
	if err != nil {
		t.Fatalf("read backup: %v", err)
	}
	if string(backup) != string(original) {
		t.Errorf("backup mismatch")
	}
}

// TestDecodeWalkSkipsPlain verifies plain files are skipped (not failed).
func TestDecodeWalkSkipsPlain(t *testing.T) {
	t.Parallel()
	dec := cipher.NewDecoder()
	files := afero.NewMemMapFs()
	if err := afero.WriteFile(files, "/r/a.yaml", []byte("foo: bar\n"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	var skips int
	err := cipher.DecodeWalkWith(context.Background(), files, "/r", dec, nil,
		cipher.WalkOptions{OnSkip: func(string, error) { skips++ }})
	if err != nil {
		t.Errorf("DecodeWalkWith: %v", err)
	}
	if skips != 1 {
		t.Errorf("skips = %d, want 1", skips)
	}
}

// TestWalkMatcherRejection verifies matcher rejections fire OnSkip.
func TestWalkMatcherRejection(t *testing.T) {
	recipient := newAge(t)
	enc := cipher.NewEncoder(cipherage.MustNewProvider(recipient))
	files := afero.NewMemMapFs()
	if err := afero.WriteFile(files, "/root/keep.yaml", []byte("foo: bar\n"), 0o600); err != nil {
		t.Fatalf("seed yaml: %v", err)
	}
	if err := afero.WriteFile(files, "/root/skip.txt", []byte("x"), 0o600); err != nil {
		t.Fatalf("seed txt: %v", err)
	}
	var skips int
	err := cipher.EncodeWalkWith(context.Background(), files, "/root", enc,
		[]cipher.FileMatcher{cipher.MatchExt(".yaml")},
		cipher.WalkOptions{OnSkip: func(string, error) { skips++ }})
	if err != nil {
		t.Fatalf("EncodeWalkWith: %v", err)
	}
	if skips != 1 {
		t.Errorf("skips = %d, want 1 (txt rejected)", skips)
	}
}

// TestMergeProvidersFlattens verifies MergeProviders collapses all keys
// from supplied providers into one group.
func TestMergeProvidersFlattens(t *testing.T) {
	recipient := newAge(t)
	groups := ageGroup(t, recipient)
	id2, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("id2: %v", err)
	}
	groups2 := ageGroup(t, id2.Recipient().String())

	merged := cipher.MergeProviders(
		cipher.StaticKeyProvider(groups...),
		cipher.StaticKeyProvider(groups2...),
	)
	out, err := merged.KeyGroups(context.Background())
	if err != nil {
		t.Fatalf("KeyGroups: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("groups = %d, want 1 (flattened)", len(out))
	}
	if len(out[0]) != 2 {
		t.Errorf("group size = %d, want 2", len(out[0]))
	}
}

// TestMergeProvidersEmpty returns nil groups when no providers yield keys.
func TestMergeProvidersEmpty(t *testing.T) {
	t.Parallel()
	merged := cipher.MergeProviders()
	out, err := merged.KeyGroups(context.Background())
	if err != nil {
		t.Fatalf("KeyGroups: %v", err)
	}
	if out != nil {
		t.Errorf("groups = %+v, want nil", out)
	}
}

// TestMergeProvidersPropagatesError surfaces a provider error.
func TestMergeProvidersPropagatesError(t *testing.T) {
	t.Parallel()
	sentinel := errors.New("bad provider")
	bad := cipher.KeyProviderFunc(func(context.Context) ([]sops.KeyGroup, error) {
		return nil, sentinel
	})
	merged := cipher.MergeProviders(bad)
	_, err := merged.KeyGroups(context.Background())
	if !errors.Is(err, sentinel) {
		t.Errorf("err = %v, want sentinel", err)
	}
}

// TestRoutedEncoderNoMatch verifies ErrNoMatchingRule passthrough.
func TestRoutedEncoderNoMatch(t *testing.T) {
	t.Parallel()
	router := cipher.RouterFunc(func(string) (cipher.KeyProvider, cipher.EncoderOptions, error) {
		return nil, cipher.EncoderOptions{}, cipher.ErrNoMatchingRule
	})
	enc := cipher.NewRoutedEncoder(router, cipher.EncoderOptions{})
	_, err := enc.Encode(context.Background(), "x.yaml", []byte("a: 1\n"))
	if !errors.Is(err, cipher.ErrNoMatchingRule) || !errors.Is(err, cipher.ErrEncode) {
		t.Errorf("err = %v, want wraps of ErrNoMatchingRule and ErrEncode", err)
	}
}

// TestNewRoutedEncoderPanicsOnNilRouter verifies the constructor panic.
func TestNewRoutedEncoderPanicsOnNilRouter(t *testing.T) {
	t.Parallel()
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic")
		}
	}()
	cipher.NewRoutedEncoder(nil, cipher.EncoderOptions{})
}

// TestNewRouterPanicsOnNilMatch verifies the constructor panic.
func TestNewRouterPanicsOnNilMatch(t *testing.T) {
	t.Parallel()
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic on nil Match")
		}
	}()
	cipher.NewRouter(cipher.Rule{Provider: cipher.StaticKeyProvider()})
}

// TestNewRouterPanicsOnNilProvider verifies the constructor panic.
func TestNewRouterPanicsOnNilProvider(t *testing.T) {
	t.Parallel()
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic on nil Provider")
		}
	}()
	cipher.NewRouter(cipher.Rule{Match: cipher.MatchAll()})
}

// TestNewShamirRulePanicsOnNilMatch verifies the constructor panic.
func TestNewShamirRulePanicsOnNilMatch(t *testing.T) {
	t.Parallel()
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic")
		}
	}()
	cipher.NewShamirRule(nil, 2, cipher.StaticKeyProvider(), cipher.StaticKeyProvider())
}

// TestNewShamirRulePanicsOnZeroThreshold verifies the constructor panic.
func TestNewShamirRulePanicsOnZeroThreshold(t *testing.T) {
	t.Parallel()
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic")
		}
	}()
	cipher.NewShamirRule(cipher.MatchAll(), 0, cipher.StaticKeyProvider())
}

// TestNewShamirRulePanicsOnNilProvider verifies the constructor panic.
func TestNewShamirRulePanicsOnNilProvider(t *testing.T) {
	t.Parallel()
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic")
		}
	}()
	cipher.NewShamirRule(cipher.MatchAll(), 1, nil)
}

// TestNewShamirRulePanicsOnInsufficientProviders verifies the constructor panic.
func TestNewShamirRulePanicsOnInsufficientProviders(t *testing.T) {
	t.Parallel()
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic")
		}
	}()
	cipher.NewShamirRule(cipher.MatchAll(), 3, cipher.StaticKeyProvider())
}

// TestRouterFirstMatchWins covers the rule-scan loop order.
func TestRouterFirstMatchWins(t *testing.T) {
	t.Parallel()
	r := cipher.NewRouter(
		cipher.Rule{
			Match:    cipher.MatchExt(".yaml"),
			Provider: cipher.StaticKeyProvider(sops.KeyGroup{}),
			Options:  cipher.EncoderOptions{EncryptedSuffix: "_first"},
		},
		cipher.Rule{
			Match:    cipher.MatchAll(),
			Provider: cipher.StaticKeyProvider(sops.KeyGroup{}),
			Options:  cipher.EncoderOptions{EncryptedSuffix: "_second"},
		},
	)
	_, opts, err := r.Resolve("a.yaml")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if opts.EncryptedSuffix != "_first" {
		t.Errorf("suffix = %q, want _first", opts.EncryptedSuffix)
	}
}

// TestRouterNoMatch returns ErrNoMatchingRule.
func TestRouterNoMatch(t *testing.T) {
	t.Parallel()
	r := cipher.NewRouter()
	_, _, err := r.Resolve("a.yaml")
	if !errors.Is(err, cipher.ErrNoMatchingRule) {
		t.Errorf("err = %v, want ErrNoMatchingRule", err)
	}
}

// TestRouterRuleOptionsOverrideBase verifies rule options override base
// options field-by-field via NewRoutedEncoder.
func TestRouterRuleOptionsOverrideBase(t *testing.T) {
	recipient := newAge(t)
	provider := cipherage.MustNewProvider(recipient)
	r := cipher.NewRouter(cipher.Rule{
		Match:    cipher.MatchAll(),
		Provider: provider,
		Options: cipher.EncoderOptions{
			EncryptedSuffix: "_secret",
		},
	})
	enc := cipher.NewRoutedEncoder(r, cipher.EncoderOptions{
		EncryptedSuffix: "_base",
	})
	out, err := enc.Encode(context.Background(), "x.yaml",
		[]byte("name: alice\nname_secret: bob\n"))
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	info, err := cipher.InspectPath("x.yaml", out)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if info.EncryptedSuffix != "_secret" {
		t.Errorf("EncryptedSuffix = %q, want _secret", info.EncryptedSuffix)
	}
}

// TestInspectErrorPaths covers the package-level Inspect error wraps.
func TestInspectErrorPaths(t *testing.T) {
	t.Parallel()
	_, err := cipher.Inspect([]byte{}, cipher.FormatFromString("yaml"))
	if !errors.Is(err, cipher.ErrNotEncrypted) {
		t.Errorf("err = %v, want ErrNotEncrypted", err)
	}
	_, err = cipher.InspectPath("x.yaml", []byte("foo: bar\n"))
	if !errors.Is(err, cipher.ErrNotEncrypted) {
		t.Errorf("InspectPath err = %v, want ErrNotEncrypted", err)
	}
}

// TestDiffRecipientsReportsAddedRemoved verifies DiffRecipients adds and
// removes are reported with stable sort.
func TestDiffRecipientsReportsAddedRemoved(t *testing.T) {
	recipient := newAge(t)
	id2, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("id2: %v", err)
	}

	encOne := cipher.NewEncoder(cipherage.MustNewProvider(recipient))
	encTwo := cipher.NewEncoder(cipherage.MustNewProvider(id2.Recipient().String()))

	plain := []byte("a: 1\n")
	before, err := encOne.Encode(context.Background(), "x.yaml", plain)
	if err != nil {
		t.Fatalf("encOne: %v", err)
	}
	after, err := encTwo.Encode(context.Background(), "x.yaml", plain)
	if err != nil {
		t.Fatalf("encTwo: %v", err)
	}

	diff, err := cipher.DiffRecipientsPath("x.yaml", before, after)
	if err != nil {
		t.Fatalf("DiffRecipientsPath: %v", err)
	}
	if diff.Empty() {
		t.Fatal("diff empty, want adds and removes")
	}
	if !strings.Contains(diff.Added[0], "age:") || !strings.Contains(diff.Removed[0], "age:") {
		t.Errorf("diff = %+v, want age recipients", diff)
	}
}

// TestDiffRecipientsBeforeErr surfaces an inspect error on the before
// argument.
func TestDiffRecipientsBeforeErr(t *testing.T) {
	t.Parallel()
	_, err := cipher.DiffRecipients(
		cipher.FormatFromString("yaml"), []byte("foo: bar\n"),
		cipher.FormatFromString("yaml"), []byte("foo: bar\n"),
	)
	if err == nil {
		t.Fatal("err = nil, want inspect failure")
	}
}

// TestFormatNameRoundTrip covers FormatName for each format.
func TestFormatNameRoundTrip(t *testing.T) {
	t.Parallel()
	names := []string{"yaml", "json", "dotenv", "ini", "binary"}
	for _, name := range names {
		f := cipher.FormatFromString(name)
		got := cipher.FormatName(f)
		if got != name {
			t.Errorf("FormatName(%q) = %q", name, got)
		}
	}
}

// TestNopLoggerNoCrash exercises the no-op logger paths.
func TestNopLoggerNoCrash(t *testing.T) {
	t.Parallel()
	cipher.NopLogger.Debugf("a %d", 1)
	cipher.NopLogger.Infof("b %d", 2)
	cipher.NopLogger.Warnf("c %d", 3)
}

// TestLoggerCallbacksFire verifies a custom Logger receives encode and
// decode lifecycle events.
func TestLoggerCallbacksFire(t *testing.T) {
	recipient := newAge(t)
	rec := &recordingLogger{}
	enc := cipher.NewEncoderWith(cipherage.MustNewProvider(recipient),
		cipher.EncoderOptions{Logger: rec})
	dec := cipher.NewDecoderWith(cipher.DecoderOptions{Logger: rec})

	encrypted, err := enc.Encode(context.Background(), "x.yaml", []byte("a: 1\n"))
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if _, err := dec.Decode(context.Background(), "x.yaml", encrypted); err != nil {
		t.Fatalf("Decode: %v", err)
	}

	if rec.debugCount == 0 {
		t.Errorf("debug calls = 0, want >0")
	}
}

// TestStaticKeyProviderReturnsCopy verifies StaticKeyProvider produces
// the configured groups.
func TestStaticKeyProviderReturnsCopy(t *testing.T) {
	t.Parallel()
	g := sops.KeyGroup{}
	provider := cipher.StaticKeyProvider(g, g)
	out, err := provider.KeyGroups(context.Background())
	if err != nil {
		t.Fatalf("KeyGroups: %v", err)
	}
	if len(out) != 2 {
		t.Errorf("groups = %d, want 2", len(out))
	}
}

// TestChainKeyProvidersConcatenates verifies group concatenation.
func TestChainKeyProvidersConcatenates(t *testing.T) {
	t.Parallel()
	left := cipher.StaticKeyProvider(sops.KeyGroup{})
	right := cipher.StaticKeyProvider(sops.KeyGroup{}, sops.KeyGroup{})
	chained := cipher.ChainKeyProviders(left, right)
	out, err := chained.KeyGroups(context.Background())
	if err != nil {
		t.Fatalf("KeyGroups: %v", err)
	}
	if len(out) != 3 {
		t.Errorf("groups = %d, want 3", len(out))
	}
}

// TestChainKeyProvidersPropagatesError verifies a provider error aborts.
func TestChainKeyProvidersPropagatesError(t *testing.T) {
	t.Parallel()
	sentinel := errors.New("blow up")
	bad := cipher.KeyProviderFunc(func(context.Context) ([]sops.KeyGroup, error) {
		return nil, sentinel
	})
	chained := cipher.ChainKeyProviders(cipher.StaticKeyProvider(), bad)
	_, err := chained.KeyGroups(context.Background())
	if !errors.Is(err, sentinel) {
		t.Errorf("err = %v, want sentinel", err)
	}
}

// TestFileMatcherFuncAdapter verifies the function adapter.
func TestFileMatcherFuncAdapter(t *testing.T) {
	t.Parallel()
	m := cipher.FileMatcherFunc(func(p string) bool { return p == "yes" })
	if !m.Match("yes") || m.Match("no") {
		t.Errorf("FileMatcherFunc misbehaving")
	}
}

// TestFollowSymlinksIgnoredOnMemFS verifies WalkOptions.FollowSymlinks
// is consulted at all (afero MemMapFs lacks symlinks so we test the
// false branch implicitly).
func TestFollowSymlinksIgnoredOnMemFS(t *testing.T) {
	t.Parallel()
	files := afero.NewMemMapFs()
	if err := afero.WriteFile(files, "/r/a.yaml", []byte("foo: bar\n"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	dec := cipher.NewDecoder()
	err := cipher.DecodeWalkWith(context.Background(), files, "/r", dec, nil,
		cipher.WalkOptions{FollowSymlinks: true})
	if err != nil {
		t.Errorf("DecodeWalkWith FollowSymlinks=true: %v", err)
	}
}

// TestFollowSymlinksDetectsCycle verifies that a symlink pointing back
// at its parent directory does not cause infinite recursion. The
// cyclic symlink is reported via OnSkip with ErrSymlinkCycle, and the
// walk completes after processing the original file.
func TestFollowSymlinksDetectsCycle(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.yaml"), []byte("foo: bar\n"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	// Symlink "loop" -> ".", so dir/loop is dir.
	if err := os.Symlink(".", filepath.Join(dir, "loop")); err != nil {
		t.Skipf("symlink not supported on this filesystem: %v", err)
	}

	files := afero.NewOsFs()
	recipient := newAge(t)
	enc := cipher.NewEncoder(cipherage.MustNewProvider(recipient))

	var (
		cycles int
		hits   int
	)
	err := cipher.EncodeWalkWith(
		context.Background(), files, dir, enc,
		[]cipher.FileMatcher{cipher.MatchExt("yaml")},
		cipher.WalkOptions{
			FollowSymlinks: true,
			OnFile:         func(string, int) { hits++ },
			OnSkip: func(_ string, reason error) {
				if errors.Is(reason, cipher.ErrSymlinkCycle) {
					cycles++
				}
			},
		},
	)
	if err != nil {
		t.Fatalf("EncodeWalkWith: %v", err)
	}
	if cycles == 0 {
		t.Error("ErrSymlinkCycle was never reported")
	}
	if hits != 1 {
		t.Errorf("hits = %d, want 1 (a.yaml processed exactly once)", hits)
	}
}

// TestWalkSerialFastPath exercises the Parallelism<=1 branch with a
// callback assertion.
func TestWalkSerialFastPath(t *testing.T) {
	recipient := newAge(t)
	enc := cipher.NewEncoder(cipherage.MustNewProvider(recipient))
	files := afero.NewMemMapFs()
	if err := afero.WriteFile(files, "/r/a.yaml", []byte("foo: bar\n"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	var hits int
	err := cipher.EncodeWalkWith(context.Background(), files, "/r", enc, nil,
		cipher.WalkOptions{Parallelism: 1, OnFile: func(string, int) { hits++ }})
	if err != nil {
		t.Fatalf("EncodeWalkWith: %v", err)
	}
	if hits != 1 {
		t.Errorf("hits = %d, want 1", hits)
	}
}

// TestWalkPropagatesReadError verifies that a read failure on a matched
// path is returned (not swallowed).
func TestWalkPropagatesReadError(t *testing.T) {
	t.Parallel()
	dec := cipher.NewDecoder()
	base := afero.NewMemMapFs()
	if err := afero.WriteFile(base, "/r/a.yaml", []byte("a"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	files := &readFailFs{Fs: base}
	err := cipher.DecodeWalkWith(context.Background(), files, "/r", dec, nil,
		cipher.WalkOptions{})
	if err == nil {
		t.Fatal("err = nil, want read failure")
	}
}

// TestStatusFunctions checks IsEncryptedPath and IsEncrypted boolean
// returns for known inputs.
func TestStatusFunctions(t *testing.T) {
	recipient := newAge(t)
	enc := cipher.NewEncoder(cipherage.MustNewProvider(recipient))
	encrypted, err := enc.Encode(context.Background(), "x.yaml", []byte("foo: bar\n"))
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if !cipher.IsEncryptedPath("x.yaml", encrypted) {
		t.Errorf("IsEncryptedPath returned false on encrypted bytes")
	}
	if cipher.IsEncryptedPath("x.yaml", []byte("foo: bar\n")) {
		t.Errorf("IsEncryptedPath returned true on plain bytes")
	}
	if !cipher.IsEncrypted(encrypted, cipher.FormatFromString("yaml")) {
		t.Errorf("IsEncrypted returned false on encrypted YAML")
	}
}

// recordingLogger captures call counts at each level.
type recordingLogger struct {
	debugCount int
	infoCount  int
	warnCount  int
}

// Debugf increments debugCount.
func (r *recordingLogger) Debugf(string, ...any) { r.debugCount++ }

// Infof increments infoCount.
func (r *recordingLogger) Infof(string, ...any) { r.infoCount++ }

// Warnf increments warnCount.
func (r *recordingLogger) Warnf(string, ...any) { r.warnCount++ }

// readFailFs returns failing reads for matched paths.
type readFailFs struct{ afero.Fs }

// Open returns an error so the walker's read step fails.
func (readFailFs) Open(string) (afero.File, error) {
	return nil, errors.New("stub read failure")
}

// itoa is a small int formatter for test paths, avoiding strconv import noise.
func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	neg := i < 0
	if neg {
		i = -i
	}
	var buf [12]byte
	pos := len(buf)
	for i > 0 {
		pos--
		buf[pos] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		pos--
		buf[pos] = '-'
	}
	return string(buf[pos:])
}
