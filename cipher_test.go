package cipher_test

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/spf13/afero"

	"github.com/dcadolph/cipher"
	cipherage "github.com/dcadolph/cipher/age"
)

// newAgeIdentity returns a fresh age identity and configures the process
// environment so the sops age master key can find the matching private
// key during decryption. Tests that call this helper must not run in
// parallel because they mutate SOPS_AGE_KEY.
func newAgeIdentity(t *testing.T) (recipient string) {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate age identity: %v", err)
	}
	t.Setenv("SOPS_AGE_KEY", id.String())
	return id.Recipient().String()
}

// TestEncoderRoundTrip exercises encode and decode against the same age
// identity for each supported format.
func TestEncoderRoundTrip(t *testing.T) {
	recipient := newAgeIdentity(t)
	kp := cipherage.NewProvider(recipient)
	enc := cipher.NewEncoder(kp)
	dec := cipher.NewDecoder()
	ctx := context.Background()

	tests := []struct {
		Path     string
		Data     []byte
		Contains []string
	}{
		// Test 0: YAML round trip.
		{
			Path:     "secrets.yaml",
			Data:     []byte("foo: bar\nbaz: qux\n"),
			Contains: []string{"foo: bar", "baz: qux"},
		},
		// Test 1: JSON round trip.
		{
			Path:     "creds.json",
			Data:     []byte(`{"user":"alice","pass":"hunter2"}`),
			Contains: []string{`"user"`, `"alice"`, `"pass"`, `"hunter2"`},
		},
		// Test 2: Dotenv round trip.
		{
			Path:     "vars.env",
			Data:     []byte("FOO=bar\nBAZ=qux\n"),
			Contains: []string{"FOO=bar", "BAZ=qux"},
		},
		// Test 3: INI round trip.
		{
			Path:     "app.ini",
			Data:     []byte("[section]\nkey=value\n"),
			Contains: []string{"[section]", "key", "value"},
		},
	}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			ciphertext, err := enc.Encode(ctx, test.Path, test.Data)
			if err != nil {
				t.Fatalf("encode: %v", err)
			}
			if !cipher.IsEncryptedPath(test.Path, ciphertext) {
				t.Fatalf("expected ciphertext to be detected as encrypted")
			}
			plaintext, err := dec.Decode(ctx, test.Path, ciphertext)
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			for _, want := range test.Contains {
				if !strings.Contains(string(plaintext), want) {
					t.Errorf("plaintext %q missing substring %q", plaintext, want)
				}
			}
		})
	}
}

// TestEncoderRejectsAlreadyEncrypted verifies the Encoder returns
// ErrAlreadyEncrypted when given sops-encrypted input.
func TestEncoderRejectsAlreadyEncrypted(t *testing.T) {
	recipient := newAgeIdentity(t)
	enc := cipher.NewEncoder(cipherage.NewProvider(recipient))
	ctx := context.Background()

	once, err := enc.Encode(ctx, "x.yaml", []byte("foo: bar\n"))
	if err != nil {
		t.Fatalf("first encode: %v", err)
	}
	_, err = enc.Encode(ctx, "x.yaml", once)
	if !errors.Is(err, cipher.ErrAlreadyEncrypted) {
		t.Fatalf("err = %v, want errors.Is ErrAlreadyEncrypted", err)
	}
}

// TestDecoderRejectsPlain verifies the Decoder returns ErrNotEncrypted
// when given unencrypted input.
func TestDecoderRejectsPlain(t *testing.T) {
	t.Parallel()
	dec := cipher.NewDecoder()
	_, err := dec.Decode(context.Background(), "x.yaml", []byte("foo: bar\n"))
	if !errors.Is(err, cipher.ErrNotEncrypted) {
		t.Fatalf("err = %v, want errors.Is ErrNotEncrypted", err)
	}
}

// TestEncoderEmptyInput verifies the Encoder reports ErrEmpty when the
// input contains no encryptable branches.
func TestEncoderEmptyInput(t *testing.T) {
	recipient := newAgeIdentity(t)
	enc := cipher.NewEncoder(cipherage.NewProvider(recipient))
	_, err := enc.Encode(context.Background(), "empty.yaml", []byte(""))
	if !errors.Is(err, cipher.ErrEmpty) {
		t.Fatalf("err = %v, want errors.Is ErrEmpty", err)
	}
}

// TestEncoderNilProviderPanics verifies the factory panics on a nil provider.
func TestEncoderNilProviderPanics(t *testing.T) {
	t.Parallel()
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic on nil KeyProvider")
		}
	}()
	_ = cipher.NewEncoder(nil)
}

// TestEncoderNoKeyGroups verifies an Encoder backed by an empty provider
// returns an error wrapping ErrNoKeyGroups.
func TestEncoderNoKeyGroups(t *testing.T) {
	t.Parallel()
	enc := cipher.NewEncoder(cipher.StaticKeyProvider())
	_, err := enc.Encode(context.Background(), "x.yaml", []byte("foo: bar\n"))
	if !errors.Is(err, cipher.ErrNoKeyGroups) {
		t.Fatalf("err = %v, want errors.Is ErrNoKeyGroups", err)
	}
	if !errors.Is(err, cipher.ErrEncode) {
		t.Fatalf("err = %v, want errors.Is ErrEncode", err)
	}
}

// TestEncoderMaxPlaintextBytes verifies the input-size guard.
func TestEncoderMaxPlaintextBytes(t *testing.T) {
	recipient := newAgeIdentity(t)
	enc := cipher.NewEncoderWith(cipherage.NewProvider(recipient),
		cipher.EncoderOptions{MaxPlaintextBytes: 8},
	)
	_, err := enc.Encode(context.Background(), "x.yaml", []byte("foo: bar\nbaz: qux\n"))
	if !errors.Is(err, cipher.ErrInputTooLarge) {
		t.Fatalf("err = %v, want errors.Is ErrInputTooLarge", err)
	}
	if !errors.Is(err, cipher.ErrEncode) {
		t.Fatalf("err = %v, want errors.Is ErrEncode", err)
	}
}

// TestEncoderWithEncryptedRegex verifies that EncoderOptions threads
// through to sops so only matching keys are encrypted.
func TestEncoderWithEncryptedRegex(t *testing.T) {
	recipient := newAgeIdentity(t)
	enc := cipher.NewEncoderWith(cipherage.NewProvider(recipient), cipher.EncoderOptions{
		EncryptedRegex: "^secret_",
	})
	dec := cipher.NewDecoder()

	plain := []byte("public: visible\nsecret_password: hunter2\n")
	ciphertext, err := enc.Encode(context.Background(), "x.yaml", plain)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if !strings.Contains(string(ciphertext), "public: visible") {
		t.Errorf("public key should remain plaintext, got:\n%s", ciphertext)
	}
	if !strings.Contains(string(ciphertext), "secret_password: ENC[") {
		t.Errorf("secret_ key should be encrypted, got:\n%s", ciphertext)
	}
	decoded, err := dec.Decode(context.Background(), "x.yaml", ciphertext)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !strings.Contains(string(decoded), "secret_password: hunter2") {
		t.Errorf("round trip lost secret value, got:\n%s", decoded)
	}
}

// TestEncodeWalkBackupSuffix verifies that the original is preserved
// at <path><suffix> when WalkOptions.BackupSuffix is set.
func TestEncodeWalkBackupSuffix(t *testing.T) {
	recipient := newAgeIdentity(t)
	enc := cipher.NewEncoder(cipherage.NewProvider(recipient))
	files := afero.NewMemMapFs()

	orig := []byte("foo: bar\n")
	if err := afero.WriteFile(files, "root/a.yaml", orig, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	err := cipher.EncodeWalkWith(
		context.Background(), files, "root", enc,
		[]cipher.FileMatcher{cipher.MatchExt("yaml")},
		cipher.WalkOptions{BackupSuffix: ".bak"},
	)
	if err != nil {
		t.Fatalf("EncodeWalkWith: %v", err)
	}
	backup, err := afero.ReadFile(files, "root/a.yaml.bak")
	if err != nil {
		t.Fatalf("read backup: %v", err)
	}
	if string(backup) != string(orig) {
		t.Errorf("backup mismatch: got %q, want %q", backup, orig)
	}
	enc2, _ := afero.ReadFile(files, "root/a.yaml")
	if !cipher.IsEncryptedPath("root/a.yaml", enc2) {
		t.Errorf("primary file not encrypted")
	}
}

// TestEncodeWalkParallel verifies bounded-concurrency walking encrypts
// every matching file across many subdirectories.
func TestEncodeWalkParallel(t *testing.T) {
	recipient := newAgeIdentity(t)
	enc := cipher.NewEncoder(cipherage.NewProvider(recipient))
	dec := cipher.NewDecoder()
	files := afero.NewMemMapFs()

	const n = 12
	for i := 0; i < n; i++ {
		p := fmt.Sprintf("root/sub%d/file.yaml", i)
		if err := afero.WriteFile(files, p, []byte("foo: bar\n"), 0o600); err != nil {
			t.Fatalf("write %q: %v", p, err)
		}
	}

	opts := cipher.WalkOptions{Parallelism: 4}
	if err := cipher.EncodeWalkWith(
		context.Background(), files, "root", enc,
		[]cipher.FileMatcher{cipher.MatchExt("yaml")}, opts,
	); err != nil {
		t.Fatalf("EncodeWalkWith: %v", err)
	}

	for i := 0; i < n; i++ {
		p := fmt.Sprintf("root/sub%d/file.yaml", i)
		data, err := afero.ReadFile(files, p)
		if err != nil {
			t.Fatalf("read %q: %v", p, err)
		}
		if !cipher.IsEncryptedPath(p, data) {
			t.Errorf("%q not encrypted after parallel walk", p)
		}
		plain, err := dec.Decode(context.Background(), p, data)
		if err != nil {
			t.Fatalf("decode %q: %v", p, err)
		}
		if !strings.Contains(string(plain), "foo: bar") {
			t.Errorf("decoded %q lost contents: %q", p, plain)
		}
	}
}

// TestEncodeWalkCtxCancelled verifies the walker aborts when ctx is cancelled.
func TestEncodeWalkCtxCancelled(t *testing.T) {
	recipient := newAgeIdentity(t)
	files := afero.NewMemMapFs()
	if err := afero.WriteFile(files, "root/a.yaml", []byte("foo: bar\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	enc := cipher.NewEncoder(cipherage.NewProvider(recipient))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := cipher.EncodeWalk(ctx, files, "root", enc, []cipher.FileMatcher{cipher.MatchExt("yaml")})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want errors.Is context.Canceled", err)
	}
}

// TestChainEncoders verifies that ChainEncoders feeds output through each
// encoder in sequence.
func TestChainEncoders(t *testing.T) {
	t.Parallel()
	upper := cipher.EncoderFunc(func(_ context.Context, _ string, data []byte) ([]byte, error) {
		return []byte(strings.ToUpper(string(data))), nil
	})
	suffix := cipher.EncoderFunc(func(_ context.Context, _ string, data []byte) ([]byte, error) {
		return append(data, '!'), nil
	})
	chain := cipher.ChainEncoders(upper, suffix)
	got, err := chain.Encode(context.Background(), "x", []byte("hello"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(got) != "HELLO!" {
		t.Fatalf("got %q, want %q", got, "HELLO!")
	}
}

// TestChainDecoders verifies that ChainDecoders feeds output through each
// decoder in sequence.
func TestChainDecoders(t *testing.T) {
	t.Parallel()
	stripBang := cipher.DecoderFunc(func(_ context.Context, _ string, d []byte) ([]byte, error) {
		return []byte(strings.TrimSuffix(string(d), "!")), nil
	})
	lower := cipher.DecoderFunc(func(_ context.Context, _ string, d []byte) ([]byte, error) {
		return []byte(strings.ToLower(string(d))), nil
	})
	chain := cipher.ChainDecoders(stripBang, lower)
	got, err := chain.Decode(context.Background(), "x", []byte("HELLO!"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(got) != "hello" {
		t.Fatalf("got %q, want %q", got, "hello")
	}
}

// TestEncodeWalkAndDecodeWalk encrypts every YAML/JSON file under a root
// directory and then decrypts them back, asserting the original bytes
// are recovered and that non-matched files are untouched.
func TestEncodeWalkAndDecodeWalk(t *testing.T) {
	recipient := newAgeIdentity(t)
	files := afero.NewMemMapFs()

	mkfile := func(path, body string) {
		if err := afero.WriteFile(files, path, []byte(body), 0o600); err != nil {
			t.Fatalf("write %q: %v", path, err)
		}
	}
	mkfile("root/a.yaml", "foo: bar\n")
	mkfile("root/sub/b.json", `{"k":"v"}`)
	mkfile("root/sub/c.txt", "leave me alone\n")

	enc := cipher.NewEncoder(cipherage.NewProvider(recipient))
	dec := cipher.NewDecoder()
	matchers := []cipher.FileMatcher{cipher.MatchExt("yaml", "json")}
	ctx := context.Background()

	var encoded []string
	encOpts := cipher.WalkOptions{
		OnFile: func(p string, _ int) { encoded = append(encoded, filepath.ToSlash(p)) },
	}
	if err := cipher.EncodeWalkWith(ctx, files, "root", enc, matchers, encOpts); err != nil {
		t.Fatalf("encode walk: %v", err)
	}

	wantEncoded := []string{"root/a.yaml", "root/sub/b.json"}
	if diff := cmp.Diff(wantEncoded, encoded, cmpopts.SortSlices(stringLess)); diff != "" {
		t.Fatalf("encoded paths mismatch (-want +got):\n%s", diff)
	}

	for _, p := range wantEncoded {
		data, err := afero.ReadFile(files, p)
		if err != nil {
			t.Fatalf("read %q: %v", p, err)
		}
		if !cipher.IsEncryptedPath(p, data) {
			t.Errorf("%q should be encrypted after walk", p)
		}
	}

	txt, _ := afero.ReadFile(files, "root/sub/c.txt")
	if string(txt) != "leave me alone\n" {
		t.Errorf("non-matched file was modified: %q", txt)
	}

	// Re-running encode should skip already-encrypted files.
	var skipped []string
	skipOpts := cipher.WalkOptions{
		OnSkip: func(p string, reason error) {
			if errors.Is(reason, cipher.ErrAlreadyEncrypted) {
				skipped = append(skipped, filepath.ToSlash(p))
			}
		},
	}
	if err := cipher.EncodeWalkWith(ctx, files, "root", enc, matchers, skipOpts); err != nil {
		t.Fatalf("second encode walk: %v", err)
	}
	if diff := cmp.Diff(wantEncoded, skipped, cmpopts.SortSlices(stringLess)); diff != "" {
		t.Fatalf("skipped paths mismatch (-want +got):\n%s", diff)
	}

	// Decode walk should round-trip back to original contents.
	if err := cipher.DecodeWalk(ctx, files, "root", dec, matchers); err != nil {
		t.Fatalf("decode walk: %v", err)
	}
	yaml, _ := afero.ReadFile(files, "root/a.yaml")
	json, _ := afero.ReadFile(files, "root/sub/b.json")
	if !strings.Contains(string(yaml), "foo: bar") {
		t.Errorf("yaml not recovered: %q", yaml)
	}
	if !strings.Contains(string(json), `"k"`) {
		t.Errorf("json not recovered: %q", json)
	}
}

// TestEncodeWalkPanicsOnNilDeps verifies factory-style guard rails.
func TestEncodeWalkPanicsOnNilDeps(t *testing.T) {
	t.Parallel()
	t.Run("nil filesystem", func(t *testing.T) {
		t.Parallel()
		defer func() {
			if r := recover(); r == nil {
				t.Fatal("expected panic on nil filesystem")
			}
		}()
		_ = cipher.EncodeWalk(context.Background(), nil, ".", cipher.NewEncoder(
			cipher.StaticKeyProvider(),
		), nil)
	})
	t.Run("nil encoder", func(t *testing.T) {
		t.Parallel()
		defer func() {
			if r := recover(); r == nil {
				t.Fatal("expected panic on nil encoder")
			}
		}()
		_ = cipher.EncodeWalk(context.Background(), afero.NewMemMapFs(), ".", nil, nil)
	})
}

// TestDecodeWalkPanicsOnNilDeps mirrors TestEncodeWalkPanicsOnNilDeps.
func TestDecodeWalkPanicsOnNilDeps(t *testing.T) {
	t.Parallel()
	t.Run("nil filesystem", func(t *testing.T) {
		t.Parallel()
		defer func() {
			if r := recover(); r == nil {
				t.Fatal("expected panic on nil filesystem")
			}
		}()
		_ = cipher.DecodeWalk(context.Background(), nil, ".", cipher.NewDecoder(), nil)
	})
	t.Run("nil decoder", func(t *testing.T) {
		t.Parallel()
		defer func() {
			if r := recover(); r == nil {
				t.Fatal("expected panic on nil decoder")
			}
		}()
		_ = cipher.DecodeWalk(context.Background(), afero.NewMemMapFs(), ".", nil, nil)
	})
}

// stringLess orders two strings for cmpopts.SortSlices.
func stringLess(a, b string) bool { return a < b }
