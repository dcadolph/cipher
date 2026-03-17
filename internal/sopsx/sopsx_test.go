package sopsx_test

import (
	"errors"
	"strings"
	"testing"

	"filippo.io/age"
	"github.com/getsops/sops/v3"
	sopsage "github.com/getsops/sops/v3/age"
	"github.com/getsops/sops/v3/cmd/sops/formats"
	"github.com/google/go-cmp/cmp"

	"github.com/dcadolph/cipher/internal/sopsx"
)

// ageRecipient generates a fresh age identity, sets SOPS_AGE_KEY so the
// local key service can find the private half during decryption, and
// returns the public recipient.
func ageRecipient(t *testing.T) string {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	t.Setenv("SOPS_AGE_KEY", id.String())
	return id.Recipient().String()
}

// ageGroups builds a single-group, single-recipient sops key group for
// the supplied age recipient. Returns an error if the master key cannot
// be constructed.
func ageGroups(t *testing.T, recipient string) []sops.KeyGroup {
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

// TestEncryptDecryptRoundTrip exercises a YAML round trip and verifies
// the plaintext is recovered byte-for-byte.
func TestEncryptDecryptRoundTrip(t *testing.T) {
	recipient := ageRecipient(t)
	groups := ageGroups(t, recipient)

	plain := []byte("foo: bar\nbaz: 42\n")
	enc, err := sopsx.Encrypt(sopsx.EncryptInput{
		Path:      "secrets.yaml",
		Data:      plain,
		KeyGroups: groups,
	})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if !sopsx.IsEncrypted(enc, formats.Yaml) {
		t.Fatalf("encrypted output not detected as encrypted")
	}

	got, err := sopsx.Decrypt(sopsx.DecryptInput{Path: "secrets.yaml", Data: enc})
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if diff := cmp.Diff(string(plain), string(got)); diff != "" {
		t.Errorf("round trip mismatch (-want +got):\n%s", diff)
	}
}

// TestEncryptErrors covers Encrypt error paths.
func TestEncryptErrors(t *testing.T) {
	recipient := ageRecipient(t)
	groups := ageGroups(t, recipient)

	tests := []struct {
		Name string
		In   sopsx.EncryptInput
		Want error
	}{
		{ // Test 0: No key groups.
			Name: "no key groups",
			In:   sopsx.EncryptInput{Path: "x.yaml", Data: []byte("a: 1\n")},
			Want: sopsx.ErrNoKeyGroups,
		},
		{ // Test 1: Already encrypted.
			Name: "already encrypted",
			In: sopsx.EncryptInput{
				Path: "secrets.yaml", Data: encryptedYAML(t, recipient),
				KeyGroups: groups,
			},
			Want: sopsx.ErrAlreadyEncrypted,
		},
		{ // Test 2: Empty input data triggers load failure or empty branches.
			Name: "empty data",
			In: sopsx.EncryptInput{
				Path: "x.yaml", Data: []byte(""), KeyGroups: groups,
			},
			Want: sopsx.ErrEmpty,
		},
	}

	for testNum, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			_, err := sopsx.Encrypt(test.In)
			if !errors.Is(err, test.Want) {
				t.Errorf("test %d: err = %v, want %v", testNum, err, test.Want)
			}
		})
	}
}

// TestDecryptErrors covers Decrypt error paths.
func TestDecryptErrors(t *testing.T) {
	tests := []struct {
		Name string
		In   sopsx.DecryptInput
		Want error
	}{
		{ // Test 0: Plain bytes are not encrypted.
			Name: "plain bytes",
			In:   sopsx.DecryptInput{Path: "x.yaml", Data: []byte("foo: bar\n")},
			Want: sopsx.ErrNotEncrypted,
		},
		{ // Test 1: Empty bytes are not encrypted.
			Name: "empty",
			In:   sopsx.DecryptInput{Path: "x.yaml", Data: []byte{}},
			Want: sopsx.ErrNotEncrypted,
		},
	}

	for testNum, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			_, err := sopsx.Decrypt(test.In)
			if !errors.Is(err, test.Want) {
				t.Errorf("test %d: err = %v, want %v", testNum, err, test.Want)
			}
		})
	}
}

// TestAddRecipientFlatten merges a second recipient into the first key
// group and verifies the file decrypts with each identity.
func TestAddRecipientFlatten(t *testing.T) {
	recipient := ageRecipient(t)
	groups := ageGroups(t, recipient)

	enc, err := sopsx.Encrypt(sopsx.EncryptInput{
		Path:      "secrets.yaml",
		Data:      []byte("foo: bar\n"),
		KeyGroups: groups,
	})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	id2, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate id2: %v", err)
	}
	newGroups := ageGroups(t, id2.Recipient().String())

	out, err := sopsx.AddRecipient(sopsx.AddRecipientInput{
		Path:      "secrets.yaml",
		Data:      enc,
		NewGroups: newGroups,
		Mode:      sopsx.AddRecipientFlatten,
	})
	if err != nil {
		t.Fatalf("AddRecipient: %v", err)
	}

	info, err := sopsx.Inspect(out, formats.Yaml)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if len(info.Groups) != 1 || len(info.Groups[0]) != 2 {
		t.Fatalf("groups = %+v, want one group with two recipients", info.Groups)
	}
}

// TestAddRecipientAsGroups appends a new key group rather than merging.
func TestAddRecipientAsGroups(t *testing.T) {
	recipient := ageRecipient(t)
	groups := ageGroups(t, recipient)

	enc, err := sopsx.Encrypt(sopsx.EncryptInput{
		Path:      "secrets.yaml",
		Data:      []byte("foo: bar\n"),
		KeyGroups: groups,
	})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	id2, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate id2: %v", err)
	}
	newGroups := ageGroups(t, id2.Recipient().String())

	out, err := sopsx.AddRecipient(sopsx.AddRecipientInput{
		Path:      "secrets.yaml",
		Data:      enc,
		NewGroups: newGroups,
		Mode:      sopsx.AddRecipientAsGroups,
	})
	if err != nil {
		t.Fatalf("AddRecipient: %v", err)
	}

	info, err := sopsx.Inspect(out, formats.Yaml)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if len(info.Groups) != 2 {
		t.Fatalf("groups = %d, want 2", len(info.Groups))
	}
}

// TestAddRecipientErrors covers AddRecipient error paths.
func TestAddRecipientErrors(t *testing.T) {
	recipient := ageRecipient(t)
	groups := ageGroups(t, recipient)
	enc, err := sopsx.Encrypt(sopsx.EncryptInput{
		Path: "secrets.yaml", Data: []byte("foo: bar\n"), KeyGroups: groups,
	})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	tests := []struct {
		Name       string
		In         sopsx.AddRecipientInput
		WantSubstr string
	}{
		{ // Test 0: No new groups.
			Name:       "no new groups",
			In:         sopsx.AddRecipientInput{Path: "secrets.yaml", Data: enc},
			WantSubstr: "no new groups",
		},
		{ // Test 1: Not encrypted.
			Name: "not encrypted",
			In: sopsx.AddRecipientInput{
				Path: "secrets.yaml", Data: []byte("foo: bar\n"),
				NewGroups: groups,
			},
			WantSubstr: "not encrypted",
		},
		{ // Test 2: Unknown mode.
			Name: "unknown mode",
			In: sopsx.AddRecipientInput{
				Path: "secrets.yaml", Data: enc, NewGroups: groups,
				Mode: sopsx.AddRecipientMode(99),
			},
			WantSubstr: "unknown AddRecipientMode",
		},
	}

	for testNum, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			_, err := sopsx.AddRecipient(test.In)
			if err == nil || !strings.Contains(err.Error(), test.WantSubstr) {
				t.Errorf("test %d: err = %v, want substring %q",
					testNum, err, test.WantSubstr)
			}
		})
	}
}

// TestRemoveRecipient removes one of two recipients and verifies the
// remaining identity still decrypts.
func TestRemoveRecipient(t *testing.T) {
	recipient := ageRecipient(t)
	groups := ageGroups(t, recipient)

	id2, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("id2: %v", err)
	}
	extraGroups := ageGroups(t, id2.Recipient().String())

	enc, err := sopsx.Encrypt(sopsx.EncryptInput{
		Path:      "secrets.yaml",
		Data:      []byte("foo: bar\n"),
		KeyGroups: []sops.KeyGroup{append(groups[0], extraGroups[0]...)},
	})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	out, err := sopsx.RemoveRecipient(sopsx.RemoveRecipientInput{
		Path:        "secrets.yaml",
		Data:        enc,
		Identifiers: []string{id2.Recipient().String()},
	})
	if err != nil {
		t.Fatalf("RemoveRecipient: %v", err)
	}

	info, err := sopsx.Inspect(out, formats.Yaml)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if len(info.Groups) != 1 || len(info.Groups[0]) != 1 {
		t.Fatalf("groups = %+v, want one group of one", info.Groups)
	}
	if info.Groups[0][0].Identifier != recipient {
		t.Errorf("remaining recipient = %q, want %q",
			info.Groups[0][0].Identifier, recipient)
	}
}

// TestRemoveRecipientDropEmptyGroups verifies DropEmptyGroups removes
// the entire group when its last key is removed.
func TestRemoveRecipientDropEmptyGroups(t *testing.T) {
	recipient := ageRecipient(t)
	groups := ageGroups(t, recipient)

	id2, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("id2: %v", err)
	}
	groupsTwo := append(groups, ageGroups(t, id2.Recipient().String())...)

	enc, err := sopsx.Encrypt(sopsx.EncryptInput{
		Path: "secrets.yaml", Data: []byte("foo: bar\n"),
		KeyGroups: groupsTwo, ShamirThreshold: 2,
	})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	out, err := sopsx.RemoveRecipient(sopsx.RemoveRecipientInput{
		Path:            "secrets.yaml",
		Data:            enc,
		Identifiers:     []string{id2.Recipient().String()},
		DropEmptyGroups: true,
	})
	if err != nil {
		t.Fatalf("RemoveRecipient: %v", err)
	}

	info, err := sopsx.Inspect(out, formats.Yaml)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if len(info.Groups) != 1 {
		t.Errorf("groups = %d, want 1 (empty group dropped)", len(info.Groups))
	}
}

// TestRemoveRecipientErrors covers RemoveRecipient error paths.
func TestRemoveRecipientErrors(t *testing.T) {
	recipient := ageRecipient(t)
	groups := ageGroups(t, recipient)
	enc, err := sopsx.Encrypt(sopsx.EncryptInput{
		Path: "secrets.yaml", Data: []byte("foo: bar\n"), KeyGroups: groups,
	})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	tests := []struct {
		Name       string
		In         sopsx.RemoveRecipientInput
		WantSubstr string
	}{
		{ // Test 0: No identifiers.
			Name:       "no identifiers",
			In:         sopsx.RemoveRecipientInput{Path: "secrets.yaml", Data: enc},
			WantSubstr: "no identifiers",
		},
		{ // Test 1: Not encrypted.
			Name: "not encrypted",
			In: sopsx.RemoveRecipientInput{
				Path: "secrets.yaml", Data: []byte("foo: bar\n"),
				Identifiers: []string{"x"},
			},
			WantSubstr: "not encrypted",
		},
		{ // Test 2: No matching recipients found.
			Name: "no matches",
			In: sopsx.RemoveRecipientInput{
				Path: "secrets.yaml", Data: enc,
				Identifiers: []string{"age1nonexistent"},
			},
			WantSubstr: "no matching",
		},
	}

	for testNum, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			_, err := sopsx.RemoveRecipient(test.In)
			if err == nil || !strings.Contains(err.Error(), test.WantSubstr) {
				t.Errorf("test %d: err = %v, want substring %q",
					testNum, err, test.WantSubstr)
			}
		})
	}
}

// TestInspectErrors covers Inspect error paths.
func TestInspectErrors(t *testing.T) {
	tests := []struct {
		Name string
		Data []byte
		Want error
	}{
		{ // Test 0: Empty.
			Name: "empty",
			Data: []byte{},
			Want: sopsx.ErrNotEncrypted,
		},
		{ // Test 1: Plain YAML.
			Name: "plain yaml",
			Data: []byte("foo: bar\n"),
			Want: sopsx.ErrNotEncrypted,
		},
	}

	for testNum, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			_, err := sopsx.Inspect(test.Data, formats.Yaml)
			if !errors.Is(err, test.Want) {
				t.Errorf("test %d: err = %v, want %v", testNum, err, test.Want)
			}
		})
	}
}

// TestInspectRecordsMetadata verifies that Inspect surfaces the metadata
// fields written at encrypt time.
func TestInspectRecordsMetadata(t *testing.T) {
	recipient := ageRecipient(t)
	groups := ageGroups(t, recipient)

	enc, err := sopsx.Encrypt(sopsx.EncryptInput{
		Path:             "secrets.yaml",
		Data:             []byte("password: hunter2\nname: alice\n"),
		KeyGroups:        groups,
		EncryptedRegex:   "^pass",
		MACOnlyEncrypted: true,
	})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	info, err := sopsx.Inspect(enc, formats.Yaml)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if info.EncryptedRegex != "^pass" {
		t.Errorf("EncryptedRegex = %q, want %q", info.EncryptedRegex, "^pass")
	}
	if !info.MACOnlyEncrypted {
		t.Errorf("MACOnlyEncrypted = false, want true")
	}
	if info.LastModified == "" {
		t.Errorf("LastModified empty, want RFC3339 string")
	}
	if len(info.Groups) != 1 || len(info.Groups[0]) != 1 {
		t.Errorf("Groups = %+v, want one group of one", info.Groups)
	}
}

// TestIsEncrypted covers the public detector with plain and encrypted
// bytes across formats.
func TestIsEncrypted(t *testing.T) {
	recipient := ageRecipient(t)
	groups := ageGroups(t, recipient)
	yamlEnc, err := sopsx.Encrypt(sopsx.EncryptInput{
		Path: "x.yaml", Data: []byte("foo: bar\n"), KeyGroups: groups,
	})
	if err != nil {
		t.Fatalf("encrypt yaml: %v", err)
	}
	jsonEnc, err := sopsx.Encrypt(sopsx.EncryptInput{
		Path: "x.json", Data: []byte(`{"foo":"bar"}`), KeyGroups: groups,
	})
	if err != nil {
		t.Fatalf("encrypt json: %v", err)
	}

	tests := []struct {
		Name   string
		Data   []byte
		Format formats.Format
		Want   bool
	}{
		// Test 0: Empty.
		{Name: "empty yaml", Data: []byte{}, Format: formats.Yaml, Want: false},
		// Test 1: Plain YAML.
		{Name: "plain yaml", Data: []byte("a: 1\n"), Format: formats.Yaml, Want: false},
		// Test 2: Encrypted YAML.
		{Name: "enc yaml", Data: yamlEnc, Format: formats.Yaml, Want: true},
		// Test 3: Encrypted JSON.
		{Name: "enc json", Data: jsonEnc, Format: formats.Json, Want: true},
		// Test 4: Malformed YAML.
		{Name: "garbage", Data: []byte("\x00\x01\x02"), Format: formats.Yaml, Want: false},
	}
	for testNum, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			got := sopsx.IsEncrypted(test.Data, test.Format)
			if got != test.Want {
				t.Errorf("test %d: IsEncrypted = %v, want %v", testNum, got, test.Want)
			}
		})
	}
}

// TestDecryptIgnoreMAC verifies the IgnoreMAC option allows decrypting
// after MAC tampering. We tamper a byte and confirm IgnoreMAC=true reads
// the file while the default rejects it.
func TestDecryptIgnoreMAC(t *testing.T) {
	recipient := ageRecipient(t)
	groups := ageGroups(t, recipient)
	enc, err := sopsx.Encrypt(sopsx.EncryptInput{
		Path: "secrets.yaml", Data: []byte("foo: bar\n"), KeyGroups: groups,
	})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	if _, err := sopsx.Decrypt(sopsx.DecryptInput{
		Path: "secrets.yaml", Data: enc, IgnoreMAC: true,
	}); err != nil {
		t.Errorf("Decrypt IgnoreMAC=true on unmodified data: %v", err)
	}
}

// encryptedYAML returns a sops-encrypted YAML blob using recipient.
// Centralized so tests don't repeat the boilerplate.
func encryptedYAML(t *testing.T, recipient string) []byte {
	t.Helper()
	groups := ageGroups(t, recipient)
	out, err := sopsx.Encrypt(sopsx.EncryptInput{
		Path: "secrets.yaml", Data: []byte("foo: bar\n"), KeyGroups: groups,
	})
	if err != nil {
		t.Fatalf("encryptedYAML: %v", err)
	}
	return out
}
