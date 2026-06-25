package main

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"filippo.io/age"

	"github.com/dcadolph/cipher"
	"github.com/dcadolph/cipher/sopsconfig"
)

// TestVersionCmd verifies `cipher version` prints something.
func TestVersionCmd(t *testing.T) {
	t.Parallel()
	cmd := newVersionCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs(nil)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if out.Len() == 0 {
		t.Errorf("version produced no output")
	}
}

// TestEncryptOutputFlag verifies --output writes encrypted bytes to the
// supplied path and stdout is not used.
func TestEncryptOutputFlag(t *testing.T) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	t.Setenv("SOPS_AGE_KEY", id.String())

	dir := t.TempDir()
	src := filepath.Join(dir, "in.yaml")
	out := filepath.Join(dir, "out.enc.yaml")
	if err := os.WriteFile(src, []byte("foo: bar\n"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}

	enc := newEncryptCmd()
	enc.SetArgs([]string{"--age", id.Recipient().String(), "--output", out, src})
	enc.SetContext(context.Background())
	if err := enc.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read out: %v", err)
	}
	if !cipher.IsEncryptedPath(out, data) {
		t.Errorf("output bytes not detected as sops-encrypted")
	}
}

// TestEncryptInPlaceStdinError verifies --in-place with PATH=- errors.
func TestEncryptInPlaceStdinError(t *testing.T) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	t.Setenv("SOPS_AGE_KEY", id.String())

	cmd := newEncryptCmd()
	cmd.SetArgs([]string{"--age", id.Recipient().String(), "--in-place", "-"})
	cmd.SetContext(context.Background())
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	err = cmd.Execute()
	if err == nil {
		t.Fatal("err = nil, want --in-place + stdin error")
	}
	if !strings.Contains(err.Error(), "in-place") {
		t.Errorf("err = %v, want in-place substring", err)
	}
}

// TestDecryptOutputFlag verifies --output writes plaintext to the
// supplied path.
func TestDecryptOutputFlag(t *testing.T) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	t.Setenv("SOPS_AGE_KEY", id.String())

	dir := t.TempDir()
	src := filepath.Join(dir, "in.yaml")
	out := filepath.Join(dir, "out.plain.yaml")
	if err := os.WriteFile(src, []byte("foo: bar\n"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}

	// Encrypt first.
	enc := newEncryptCmd()
	enc.SetArgs([]string{"--age", id.Recipient().String(), "-i", src})
	enc.SetContext(context.Background())
	if err := enc.Execute(); err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	dec := newDecryptCmd()
	dec.SetArgs([]string{"--output", out, src})
	dec.SetContext(context.Background())
	if err := dec.Execute(); err != nil {
		t.Fatalf("decrypt: %v", err)
	}

	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read out: %v", err)
	}
	if !strings.Contains(string(data), "foo: bar") {
		t.Errorf("plaintext = %q, missing foo:bar", data)
	}
}

// TestDecryptInPlaceStdinError verifies --in-place with PATH=- errors.
func TestDecryptInPlaceStdinError(t *testing.T) {
	t.Parallel()
	cmd := newDecryptCmd()
	cmd.SetArgs([]string{"--in-place", "-"})
	cmd.SetContext(context.Background())
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	err := cmd.Execute()
	if err == nil {
		t.Fatal("err = nil, want stdin/in-place error")
	}
}

// TestPrecommitCmdFlagsViolation verifies the CLI surfaces violations
// when scanning explicit paths.
func TestPrecommitCmdFlagsViolation(t *testing.T) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	recipient := id.Recipient().String()

	dir := t.TempDir()
	cfgBody := fmt.Sprintf(
		"creation_rules:\n  - path_regex: secrets/.*\\.yaml$\n    age: %s\n",
		recipient,
	)
	if err := os.WriteFile(filepath.Join(dir, sopsconfig.ConfigFileName),
		[]byte(cfgBody), 0o600); err != nil {
		t.Fatalf("cfg: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "secrets"), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	plain := filepath.Join(dir, "secrets", "leaky.yaml")
	if err := os.WriteFile(plain, []byte("foo: bar\n"), 0o600); err != nil {
		t.Fatalf("write plain: %v", err)
	}

	cmd := newPrecommitCmd()
	cmd.SetArgs([]string{"--config", dir, plain})
	cmd.SetContext(context.Background())
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	err = cmd.Execute()
	if err == nil {
		t.Fatal("err = nil, want violation")
	}
}

// TestPrecommitCmdClean verifies precommit reports no violations when
// the supplied path is sops-encrypted.
func TestPrecommitCmdClean(t *testing.T) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	t.Setenv("SOPS_AGE_KEY", id.String())
	recipient := id.Recipient().String()

	dir := t.TempDir()
	cfgBody := fmt.Sprintf(
		"creation_rules:\n  - path_regex: secrets/.*\\.yaml$\n    age: %s\n",
		recipient,
	)
	if err := os.WriteFile(filepath.Join(dir, sopsconfig.ConfigFileName),
		[]byte(cfgBody), 0o600); err != nil {
		t.Fatalf("cfg: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "secrets"), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	srcPath := filepath.Join(dir, "secrets", "good.yaml")
	if err := os.WriteFile(srcPath, []byte("foo: bar\n"), 0o600); err != nil {
		t.Fatalf("seed src: %v", err)
	}
	enc := newEncryptCmd()
	enc.SetArgs([]string{"--age", recipient, "-i", srcPath})
	enc.SetContext(context.Background())
	if err := enc.Execute(); err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	cmd := newPrecommitCmd()
	cmd.SetArgs([]string{"--config", dir, filepath.Join(dir, "secrets", "good.yaml")})
	cmd.SetContext(context.Background())
	if err := cmd.Execute(); err != nil {
		t.Errorf("precommit on encrypted file: %v", err)
	}
}

// TestProviderFlagsKeyProvider exercises every recipient flag at least
// once (returns provider, no Encode happens here).
func TestProviderFlagsKeyProvider(t *testing.T) {
	t.Parallel()
	tests := []struct {
		Name string
		Args func(*providerFlags)
		Want bool
	}{
		{Name: "age", Args: func(p *providerFlags) { p.age = "age1qyqsz" }, Want: true},
		{Name: "kms", Args: func(p *providerFlags) { p.kms = "arn:aws:kms:us-east-1:111111111111:key/x" }, Want: true},
		{Name: "gcpkms", Args: func(p *providerFlags) {
			p.gcpkms = "projects/p/locations/global/keyRings/r/cryptoKeys/k"
		}, Want: true},
		{Name: "vault", Args: func(p *providerFlags) {
			p.vault = "https://vault.example.com:8200/v1/transit/keys/keyName"
		}, Want: true},
		{Name: "azkv", Args: func(p *providerFlags) {
			p.azkv = "https://myvault.vault.azure.net/keys/k/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		}, Want: true},
		{Name: "pgp", Args: func(p *providerFlags) { p.pgp = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" }, Want: true},
	}
	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			t.Parallel()
			p := &providerFlags{}
			test.Args(p)
			kp, err := p.keyProvider()
			if err != nil {
				t.Errorf("keyProvider: %v", err)
			}
			if kp == nil {
				t.Error("kp = nil")
			}
		})
	}
}

// TestProviderFlagsKeyProviderMerged exercises the multi-provider branch
// where MergeProviders wraps two backends.
func TestProviderFlagsKeyProviderMerged(t *testing.T) {
	t.Parallel()
	p := &providerFlags{
		age: "age1qyqsz",
		pgp: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
	}
	kp, err := p.keyProvider()
	if err != nil {
		t.Fatalf("keyProvider: %v", err)
	}
	if kp == nil {
		t.Fatal("kp nil")
	}
}

// TestEncoderOptionsThreadThrough verifies the new encoder-tuning
// flags propagate from providerFlags into cipher.EncoderOptions.
func TestEncoderOptionsThreadThrough(t *testing.T) {
	t.Parallel()
	p := &providerFlags{
		encryptedRegex:    "^secret_",
		unencryptedRegex:  "^public_",
		encryptedSuffix:   "_enc",
		unencryptedSuffix: "_plain",
		macOnlyEncrypted:  true,
		shamirThreshold:   2,
	}
	got := p.encoderOptions()
	if got.EncryptedRegex != "^secret_" {
		t.Errorf("EncryptedRegex = %q, want %q", got.EncryptedRegex, "^secret_")
	}
	if got.UnencryptedRegex != "^public_" {
		t.Errorf("UnencryptedRegex = %q, want %q", got.UnencryptedRegex, "^public_")
	}
	if got.EncryptedSuffix != "_enc" {
		t.Errorf("EncryptedSuffix = %q, want %q", got.EncryptedSuffix, "_enc")
	}
	if got.UnencryptedSuffix != "_plain" {
		t.Errorf("UnencryptedSuffix = %q, want %q", got.UnencryptedSuffix, "_plain")
	}
	if got.MAC != cipher.MACOnEncrypted {
		t.Errorf("MAC = %d, want MACOnEncrypted", got.MAC)
	}
	if got.ShamirThreshold != 2 {
		t.Errorf("ShamirThreshold = %d, want 2", got.ShamirThreshold)
	}
}

// TestProviderFlagsKMSWithContext exercises the AWS KMS branch with a
// repeated --kms-context entry.
func TestProviderFlagsKMSWithContext(t *testing.T) {
	t.Parallel()
	p := &providerFlags{
		kms:    "arn:aws:kms:us-east-1:111111111111:key/x",
		awsCtx: []string{"team=cipher", "env=test"},
	}
	if _, err := p.keyProvider(); err != nil {
		t.Errorf("keyProvider: %v", err)
	}
}

// TestProviderFlagsKMSBadContext verifies parseAWSContext rejects bad
// entries.
func TestProviderFlagsKMSBadContext(t *testing.T) {
	t.Parallel()
	p := &providerFlags{
		kms:    "arn:aws:kms:us-east-1:111111111111:key/x",
		awsCtx: []string{"no_equals_sign"},
	}
	if _, err := p.keyProvider(); err == nil {
		t.Error("err = nil, want bad-context error")
	}
}

// TestProviderFlagsKeyProviderNoneSet verifies the empty-state error.
func TestProviderFlagsKeyProviderNoneSet(t *testing.T) {
	t.Parallel()
	p := &providerFlags{}
	_, err := p.keyProvider()
	if err == nil {
		t.Fatal("err = nil, want missing-recipient error")
	}
	if !strings.Contains(err.Error(), "recipient") {
		t.Errorf("err = %v, want recipient substring", err)
	}
}

// TestProviderFlagsRouterReturnsNilWhenNoConfig verifies the early
// nil return.
func TestProviderFlagsRouterReturnsNilWhenNoConfig(t *testing.T) {
	t.Parallel()
	p := &providerFlags{}
	router, err := p.router()
	if err != nil {
		t.Errorf("router: %v", err)
	}
	if router != nil {
		t.Errorf("router = %T, want nil", router)
	}
}

// TestProviderFlagsRouterFromConfig parses an on-disk .sops.yaml and
// returns a non-nil router.
func TestProviderFlagsRouterFromConfig(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	body := "creation_rules:\n  - path_regex: .*\\.yaml$\n    age: age1qyqsz\n"
	if err := os.WriteFile(filepath.Join(dir, sopsconfig.ConfigFileName),
		[]byte(body), 0o600); err != nil {
		t.Fatalf("cfg: %v", err)
	}
	p := &providerFlags{config: dir}
	router, err := p.router()
	if err != nil {
		t.Fatalf("router: %v", err)
	}
	if router == nil {
		t.Fatal("router nil")
	}
}

// TestProviderFlagsResolveEncoderUsesRouter verifies the routed encoder
// path is selected when --config is set.
func TestProviderFlagsResolveEncoderUsesRouter(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	body := "creation_rules:\n  - path_regex: .*\\.yaml$\n    age: age1qyqsz\n"
	if err := os.WriteFile(filepath.Join(dir, sopsconfig.ConfigFileName),
		[]byte(body), 0o600); err != nil {
		t.Fatalf("cfg: %v", err)
	}
	p := &providerFlags{config: dir}
	enc, err := p.resolveEncoder(nil)
	if err != nil {
		t.Fatalf("resolveEncoder: %v", err)
	}
	if enc == nil {
		t.Fatal("encoder nil")
	}
}

// TestPickEditor covers each preference branch.
func TestPickEditor(t *testing.T) {
	t.Setenv("EDITOR", "")
	t.Setenv("VISUAL", "")
	if got := pickEditor("vim"); got != "vim" {
		t.Errorf("pickEditor(vim) = %q, want vim", got)
	}
	if got := pickEditor(""); got != "vi" {
		t.Errorf("pickEditor(empty) = %q, want vi", got)
	}
	t.Setenv("VISUAL", "nvim")
	if got := pickEditor(""); got != "nvim" {
		t.Errorf("pickEditor(visual) = %q, want nvim", got)
	}
	t.Setenv("EDITOR", "nano")
	if got := pickEditor(""); got != "nano" {
		t.Errorf("pickEditor(editor) = %q, want nano", got)
	}
}

// TestShellQuote covers the single-quote escaping helper.
func TestShellQuote(t *testing.T) {
	t.Parallel()
	tests := map[string]string{
		"abc":         `'abc'`,
		"with space":  `'with space'`,
		"it's":        `'it'\''s'`,
		"two''quotes": `'two'\'''\''quotes'`,
	}
	for in, want := range tests {
		if got := shellQuote(in); got != want {
			t.Errorf("shellQuote(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestLaunchEditorRoundTrip drives launchEditor with `cat` so the temp
// file is unchanged when the editor returns. This exercises the temp
// dir creation, write, and read paths.
func TestLaunchEditorRoundTrip(t *testing.T) {
	t.Parallel()
	got, err := launchEditor("true", "/tmp/orig.yaml", []byte("plain content\n"))
	if err != nil {
		t.Fatalf("launchEditor: %v", err)
	}
	if string(got) != "plain content\n" {
		t.Errorf("got = %q, want unchanged", got)
	}
}

// TestLaunchEditorErrorPropagation verifies a failing editor returns an error.
func TestLaunchEditorErrorPropagation(t *testing.T) {
	t.Parallel()
	_, err := launchEditor("false", "/tmp/orig.yaml", []byte("x"))
	if err == nil {
		t.Fatal("err = nil, want editor exit error")
	}
}

// TestEditCmdNoTTYReturnsError verifies the edit cobra command fails
// fast when there is no recipient flag.
func TestEditCmdNoRecipient(t *testing.T) {
	t.Parallel()
	cmd := newEditCmd()
	cmd.SetArgs([]string{"/tmp/nonexistent.yaml"})
	cmd.SetContext(context.Background())
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	if err := cmd.Execute(); err == nil {
		t.Fatal("err = nil, want missing-recipient error")
	}
}

// TestAddRecipientCmdRoundTrip drives `cipher add-recipient` against an
// encrypted file and verifies the second recipient lands.
func TestAddRecipientCmdRoundTrip(t *testing.T) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("id: %v", err)
	}
	t.Setenv("SOPS_AGE_KEY", id.String())

	dir := t.TempDir()
	target := filepath.Join(dir, "secrets.yaml")
	if err := os.WriteFile(target, []byte("foo: bar\n"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}

	enc := newEncryptCmd()
	enc.SetArgs([]string{"--age", id.Recipient().String(), "-i", target})
	enc.SetContext(context.Background())
	if err := enc.Execute(); err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	id2, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("id2: %v", err)
	}
	add := newAddRecipientCmd()
	add.SetArgs([]string{"--age", id2.Recipient().String(), "-i", target})
	add.SetContext(context.Background())
	if err := add.Execute(); err != nil {
		t.Fatalf("add-recipient: %v", err)
	}

	data, _ := os.ReadFile(target)
	info, err := cipher.InspectPath(target, data)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if len(info.Groups) != 1 || len(info.Groups[0]) != 2 {
		t.Errorf("groups = %+v, want one group of two", info.Groups)
	}
}

// TestRemoveRecipientCmdRoundTrip drives `cipher remove-recipient`.
func TestRemoveRecipientCmdRoundTrip(t *testing.T) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("id: %v", err)
	}
	t.Setenv("SOPS_AGE_KEY", id.String())
	id2, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("id2: %v", err)
	}

	dir := t.TempDir()
	target := filepath.Join(dir, "secrets.yaml")
	if err := os.WriteFile(target, []byte("foo: bar\n"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}

	enc := newEncryptCmd()
	enc.SetArgs([]string{
		"--age", id.Recipient().String() + "," + id2.Recipient().String(),
		"-i", target,
	})
	enc.SetContext(context.Background())
	if err := enc.Execute(); err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	rm := newRemoveRecipientCmd()
	rm.SetArgs([]string{"-i", target, id2.Recipient().String()})
	rm.SetContext(context.Background())
	if err := rm.Execute(); err != nil {
		t.Fatalf("remove-recipient: %v", err)
	}

	data, _ := os.ReadFile(target)
	info, err := cipher.InspectPath(target, data)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if len(info.Groups) != 1 || len(info.Groups[0]) != 1 {
		t.Errorf("groups = %+v, want one group of one", info.Groups)
	}
}

// TestRotateCmdEndToEnd drives `cipher rotate` against an encrypted file.
func TestRotateCmdEndToEnd(t *testing.T) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("id: %v", err)
	}
	t.Setenv("SOPS_AGE_KEY", id.String())

	dir := t.TempDir()
	target := filepath.Join(dir, "secrets.yaml")
	if err := os.WriteFile(target, []byte("foo: bar\n"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}

	enc := newEncryptCmd()
	enc.SetArgs([]string{"--age", id.Recipient().String(), "-i", target})
	enc.SetContext(context.Background())
	if err := enc.Execute(); err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	before, _ := os.ReadFile(target)

	rot := newRotateCmd()
	rot.SetArgs([]string{"--age", id.Recipient().String(), target})
	rot.SetContext(context.Background())
	if err := rot.Execute(); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	after, _ := os.ReadFile(target)
	if bytes.Equal(before, after) {
		t.Errorf("rotated file identical to pre-rotation copy")
	}
}

// TestWalkRotateCmdEndToEnd drives `cipher walk rotate`.
func TestWalkRotateCmdEndToEnd(t *testing.T) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("id: %v", err)
	}
	t.Setenv("SOPS_AGE_KEY", id.String())

	dir := t.TempDir()
	target := filepath.Join(dir, "a.yaml")
	if err := os.WriteFile(target, []byte("foo: bar\n"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}

	enc := newEncryptCmd()
	enc.SetArgs([]string{"--age", id.Recipient().String(), "-i", target})
	enc.SetContext(context.Background())
	if err := enc.Execute(); err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	before, _ := os.ReadFile(target)

	walk := newWalkCmd()
	walk.SetArgs([]string{"rotate", "--age", id.Recipient().String(), dir})
	walk.SetContext(context.Background())
	if err := walk.Execute(); err != nil {
		t.Fatalf("walk rotate: %v", err)
	}
	after, _ := os.ReadFile(target)
	if bytes.Equal(before, after) {
		t.Errorf("walk rotate left file unchanged")
	}
}

// TestWalkFlagsMatchersRegex verifies the --regex branch.
func TestWalkFlagsMatchersRegex(t *testing.T) {
	t.Parallel()
	w := &walkFlags{regex: `\.yaml$`}
	got, err := w.matchers()
	if err != nil {
		t.Fatalf("matchers: %v", err)
	}
	if len(got) != 1 || !got[0].Match("x.yaml") || got[0].Match("x.txt") {
		t.Errorf("regex matcher misbehaving: %+v", got)
	}
}

// TestWalkFlagsMatchersBadRegex surfaces the regex compile error.
func TestWalkFlagsMatchersBadRegex(t *testing.T) {
	t.Parallel()
	w := &walkFlags{regex: "["}
	if _, err := w.matchers(); err == nil {
		t.Fatal("err = nil, want regex error")
	}
}

// TestBuildCheckerFallsBackToCwd verifies buildChecker walks upward from
// the current dir when --config is empty.
func TestBuildCheckerFallsBackToCwd(t *testing.T) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("id: %v", err)
	}
	recipient := id.Recipient().String()

	dir := t.TempDir()
	cfgBody := fmt.Sprintf(
		"creation_rules:\n  - path_regex: secrets/.*\\.yaml$\n    age: %s\n",
		recipient,
	)
	if err := os.WriteFile(filepath.Join(dir, sopsconfig.ConfigFileName),
		[]byte(cfgBody), 0o600); err != nil {
		t.Fatalf("cfg: %v", err)
	}

	prevWD, _ := os.Getwd()
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(prevWD) })

	_, err = buildChecker("", 0)
	if err != nil {
		t.Errorf("buildChecker: %v", err)
	}
}

// TestBuildCheckerExplicit verifies the explicit path branch.
func TestBuildCheckerExplicit(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cfgBody := "creation_rules:\n  - path_regex: .*\n    age: age1qyqsz\n"
	if err := os.WriteFile(filepath.Join(dir, sopsconfig.ConfigFileName),
		[]byte(cfgBody), 0o600); err != nil {
		t.Fatalf("cfg: %v", err)
	}
	if _, err := buildChecker(dir, 0); err != nil {
		t.Errorf("buildChecker: %v", err)
	}
}

// TestReadPathOrStdinFile covers the file branch of readPathOrStdin.
func TestReadPathOrStdinFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "in.txt")
	if err := os.WriteFile(path, []byte("hello"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	got, err := readPathOrStdin(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != "hello" {
		t.Errorf("got = %q, want hello", got)
	}
}

// TestReadPathOrStdinMissing covers the read-error branch.
func TestReadPathOrStdinMissing(t *testing.T) {
	t.Parallel()
	_, err := readPathOrStdin(filepath.Join(t.TempDir(), "missing.txt"))
	if err == nil {
		t.Fatal("err = nil, want missing-file")
	}
}

// TestWritePathOrStdoutFile covers the file branch of writePathOrStdout.
func TestWritePathOrStdoutFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "out.txt")
	if err := writePathOrStdout(path, []byte("hello")); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, _ := os.ReadFile(path)
	if string(got) != "hello" {
		t.Errorf("got = %q, want hello", got)
	}
}

// TestWritePathOrStdoutPreservesPerm exercises the stat branch on an
// existing file.
func TestWritePathOrStdoutPreservesPerm(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "out.txt")
	if err := os.WriteFile(path, []byte("seed"), 0o640); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := writePathOrStdout(path, []byte("replaced")); err != nil {
		t.Fatalf("write: %v", err)
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0o640 {
		t.Errorf("perm = %v, want 0o640", info.Mode().Perm())
	}
}

// TestDemoCmdServesIndex spins up the embedded demo server on a free
// port and asserts the index page is reachable.
func TestDemoCmdServesIndex(t *testing.T) {
	t.Parallel()

	mux, err := newDemoMux()
	if err != nil {
		t.Fatalf("newDemoMux: %v", err)
	}
	srv := httpServerOnFreePort(t, mux)
	defer func() { _ = srv.Close() }()

	resp, err := httpGet(t, srv, "/")
	if err != nil {
		t.Fatalf("get /: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
}

// TestDemoCmdServesExplainer exercises the explainer route.
func TestDemoCmdServesExplainer(t *testing.T) {
	t.Parallel()

	mux, err := newDemoMux()
	if err != nil {
		t.Fatalf("newDemoMux: %v", err)
	}
	srv := httpServerOnFreePort(t, mux)
	defer func() { _ = srv.Close() }()

	resp, err := httpGet(t, srv, "/explainer/tour")
	if err != nil {
		t.Fatalf("get explainer: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
}

// TestDemoCmdRejectsUnknownExplainer verifies isKnownExplainer is
// consulted by the router.
func TestDemoCmdRejectsUnknownExplainer(t *testing.T) {
	t.Parallel()

	mux, err := newDemoMux()
	if err != nil {
		t.Fatalf("newDemoMux: %v", err)
	}
	srv := httpServerOnFreePort(t, mux)
	defer func() { _ = srv.Close() }()

	resp, err := httpGet(t, srv, "/explainer/bogus")
	if err != nil {
		t.Fatalf("get unknown explainer: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusOK {
		t.Errorf("status = %d, want non-200 for unknown explainer", resp.StatusCode)
	}
}

// TestIsKnownExplainerKnown verifies the canonical list is honored.
func TestIsKnownExplainerKnown(t *testing.T) {
	t.Parallel()
	for _, slug := range demoExplainers {
		if !isKnownExplainer(slug) {
			t.Errorf("isKnownExplainer(%q) = false, want true", slug)
		}
	}
}

// TestIsKnownExplainerRejectsBogus verifies the canonical list rejects
// strings not in the list.
func TestIsKnownExplainerRejectsBogus(t *testing.T) {
	t.Parallel()
	if isKnownExplainer("bogus") {
		t.Errorf("isKnownExplainer(bogus) = true, want false")
	}
}

// httpServerOnFreePort starts an http.Server on a free localhost port
// and registers cleanup with t.Cleanup. Tests should use the returned
// server's Listener.Addr to derive the URL.
func httpServerOnFreePort(t *testing.T, h http.Handler) *http.Server {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &http.Server{Handler: h, ReadHeaderTimeout: time.Second}
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(func() { _ = srv.Close() })
	// Attach the listener's address for callers.
	srv.Addr = lis.Addr().String()
	return srv
}

// httpGet issues a GET to the supplied server at path and returns the
// response.
func httpGet(t *testing.T, srv *http.Server, path string) (*http.Response, error) {
	t.Helper()
	url := "http://" + srv.Addr + path
	client := &http.Client{Timeout: 3 * time.Second}
	return client.Get(url)
}
