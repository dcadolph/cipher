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

// TestNewRouterFirstMatch verifies first-match-wins semantics and the
// ErrNoMatchingRule fallback.
func TestNewRouterFirstMatch(t *testing.T) {
	t.Parallel()
	// Each provider returns a distinguishing tag via its EncoderOptions
	// so the test can identify which rule matched without relying on
	// pointer/interface equality (KeyProvider may be uncomparable).
	router := cipher.NewRouter(
		cipher.Rule{
			Match:    cipher.MatchExt("yaml"),
			Provider: cipher.StaticKeyProvider(),
			Options:  cipher.EncoderOptions{EncryptedRegex: "yaml-rule"},
		},
		cipher.Rule{
			Match:    cipher.MatchExt("json"),
			Provider: cipher.StaticKeyProvider(),
			Options:  cipher.EncoderOptions{EncryptedRegex: "json-rule"},
		},
	)
	_, opts, err := router.Resolve("x.yaml")
	if err != nil {
		t.Fatalf("Resolve yaml: %v", err)
	}
	if opts.EncryptedRegex != "yaml-rule" {
		t.Errorf("yaml resolved to %q, want yaml-rule", opts.EncryptedRegex)
	}
	_, opts, err = router.Resolve("x.json")
	if err != nil {
		t.Fatalf("Resolve json: %v", err)
	}
	if opts.EncryptedRegex != "json-rule" {
		t.Errorf("json resolved to %q, want json-rule", opts.EncryptedRegex)
	}
	_, _, err = router.Resolve("x.txt")
	if !errors.Is(err, cipher.ErrNoMatchingRule) {
		t.Errorf("err = %v, want errors.Is ErrNoMatchingRule", err)
	}
}

// TestNewRoutedEncoderMergesOptions verifies that per-rule options
// override base options for the matched path.
func TestNewRoutedEncoderMergesOptions(t *testing.T) {
	recipient := newAgeIdentity(t)
	kp := cipherage.NewProvider(recipient)
	router := cipher.NewRouter(cipher.Rule{
		Match:    cipher.MatchAll(),
		Provider: kp,
		Options:  cipher.EncoderOptions{EncryptedRegex: "^secret_"},
	})
	enc := cipher.NewRoutedEncoder(router, cipher.EncoderOptions{})
	ct, err := enc.Encode(
		context.Background(), "x.yaml",
		[]byte("public: visible\nsecret_password: hunter2\n"),
	)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	out := string(ct)
	if !strings.Contains(out, "public: visible") {
		t.Errorf("public key should remain plaintext, got:\n%s", out)
	}
	if !strings.Contains(out, "secret_password: ENC[") {
		t.Errorf("secret_ key should be encrypted, got:\n%s", out)
	}
}

// TestNewShamirRule verifies that a Shamir rule produces a router whose
// resulting Encoder requires all groups to decrypt by default.
func TestNewShamirRule(t *testing.T) {
	r1 := newAgeIdentity(t)
	id2, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	r2 := id2.Recipient().String()

	rule := cipher.NewShamirRule(
		cipher.MatchAll(), 2,
		cipherage.NewProvider(r1),
		cipherage.NewProvider(r2),
	)
	if rule.Options.ShamirThreshold != 2 {
		t.Errorf("ShamirThreshold = %d, want 2", rule.Options.ShamirThreshold)
	}
	router := cipher.NewRouter(rule)
	enc := cipher.NewRoutedEncoder(router, cipher.EncoderOptions{})
	out, err := enc.Encode(context.Background(), "x.yaml", []byte("foo: bar\n"))
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	info, err := cipher.InspectPath("x.yaml", out)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if len(info.Groups) != 2 {
		t.Errorf("groups = %d, want 2", len(info.Groups))
	}
	if info.ShamirThreshold != 2 {
		t.Errorf("ShamirThreshold = %d, want 2", info.ShamirThreshold)
	}
}

// TestNewShamirRulePanics verifies the guard rails.
func TestNewShamirRulePanics(t *testing.T) {
	t.Parallel()
	tests := []struct {
		Name string
		Run  func()
	}{
		{Name: "nil match", Run: func() {
			cipher.NewShamirRule(nil, 1, cipher.StaticKeyProvider())
		}},
		{Name: "zero threshold", Run: func() {
			cipher.NewShamirRule(cipher.MatchAll(), 0, cipher.StaticKeyProvider())
		}},
		{Name: "fewer providers than threshold", Run: func() {
			cipher.NewShamirRule(cipher.MatchAll(), 2, cipher.StaticKeyProvider())
		}},
	}
	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			t.Parallel()
			defer func() {
				if r := recover(); r == nil {
					t.Fatal("expected panic")
				}
			}()
			test.Run()
		})
	}
}

