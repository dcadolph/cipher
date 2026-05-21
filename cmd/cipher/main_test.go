package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"

	"github.com/dcadolph/cipher"
)

// TestEncryptThenDecrypt drives the CLI end-to-end: encrypt a temp
// file with --in-place using --age, then decrypt it back to stdout.
func TestEncryptThenDecrypt(t *testing.T) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	t.Setenv("SOPS_AGE_KEY", id.String())

	dir := t.TempDir()
	target := filepath.Join(dir, "secrets.yaml")
	if err := os.WriteFile(target, []byte("foo: bar\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	enc := newEncryptCmd()
	enc.SetArgs([]string{"--age", id.Recipient().String(), "--in-place", target})
	enc.SetContext(context.Background())
	if err := enc.Execute(); err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	encrypted, _ := os.ReadFile(target)
	if !cipher.IsEncryptedPath(target, encrypted) {
		t.Fatalf("file not encrypted after CLI encrypt")
	}

	dec := newDecryptCmd()
	dec.SetArgs([]string{target})
	dec.SetContext(context.Background())
	var stdout bytes.Buffer
	dec.SetOut(&stdout)

	// Redirect process stdout so the command writes through writePathOrStdout.
	origStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdout = w
	t.Cleanup(func() { os.Stdout = origStdout })

	if err := dec.Execute(); err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	_ = w.Close()
	var pipeOut bytes.Buffer
	_, _ = pipeOut.ReadFrom(r)
	if !strings.Contains(pipeOut.String(), "foo: bar") {
		t.Errorf("decrypted output missing original value, got:\n%s", pipeOut.String())
	}
}

// TestWalkEncryptDecrypt verifies walk subcommands across a small
// directory tree.
func TestWalkEncryptDecrypt(t *testing.T) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	t.Setenv("SOPS_AGE_KEY", id.String())

	dir := t.TempDir()
	files := []string{
		filepath.Join(dir, "a.yaml"),
		filepath.Join(dir, "sub", "b.yaml"),
	}
	if err := os.MkdirAll(filepath.Dir(files[1]), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	for _, p := range files {
		if err := os.WriteFile(p, []byte("foo: bar\n"), 0o600); err != nil {
			t.Fatalf("write %q: %v", p, err)
		}
	}

	walk := newWalkCmd()
	walk.SetArgs([]string{"encrypt", "--age", id.Recipient().String(), dir})
	walk.SetContext(context.Background())
	if err := walk.Execute(); err != nil {
		t.Fatalf("walk encrypt: %v", err)
	}
	for _, p := range files {
		data, _ := os.ReadFile(p)
		if !cipher.IsEncryptedPath(p, data) {
			t.Errorf("%q not encrypted after walk", p)
		}
	}

	walk2 := newWalkCmd()
	walk2.SetArgs([]string{"decrypt", dir})
	walk2.SetContext(context.Background())
	if err := walk2.Execute(); err != nil {
		t.Fatalf("walk decrypt: %v", err)
	}
	for _, p := range files {
		data, _ := os.ReadFile(p)
		if !strings.Contains(string(data), "foo: bar") {
			t.Errorf("%q not restored after walk decrypt: %q", p, data)
		}
	}
}

// TestEncryptRequiresRecipient verifies the CLI errors when no
// recipient flag is supplied.
func TestEncryptRequiresRecipient(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	target := filepath.Join(dir, "x.yaml")
	if err := os.WriteFile(target, []byte("foo: bar\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	enc := newEncryptCmd()
	enc.SetArgs([]string{target})
	enc.SetContext(context.Background())
	enc.SilenceUsage = true
	enc.SilenceErrors = true
	if err := enc.Execute(); err == nil {
		t.Fatal("expected error for missing recipient flags")
	}
}
