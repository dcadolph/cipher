package cipher

import "testing"

// TestIsEncryptedPlainInput verifies that unencrypted bytes are not
// classified as sops-encrypted.
func TestIsEncryptedPlainInput(t *testing.T) {
	t.Parallel()
	tests := []struct {
		Name   string
		Data   []byte
		Format Format
	}{
		// Test 0: plain YAML.
		{Name: "plain yaml", Data: []byte("foo: bar\n"), Format: FormatYAML},
		// Test 1: plain JSON.
		{Name: "plain json", Data: []byte(`{"k":"v"}`), Format: FormatJSON},
		// Test 2: empty.
		{Name: "empty", Data: nil, Format: FormatYAML},
	}
	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			t.Parallel()
			if IsEncrypted(test.Data, test.Format) {
				t.Errorf("IsEncrypted(%q, %v) = true, want false", test.Data, test.Format)
			}
		})
	}
}

// TestIsEncryptedPathDispatch verifies IsEncryptedPath uses path-based
// format detection.
func TestIsEncryptedPathDispatch(t *testing.T) {
	t.Parallel()
	if IsEncryptedPath("a.yaml", []byte("foo: bar\n")) {
		t.Error("plain YAML reported as encrypted")
	}
}
