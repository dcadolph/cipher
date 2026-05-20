package atomic_test

import (
	"io/fs"
	"testing"

	"github.com/spf13/afero"

	"github.com/dcadolph/cipher/internal/atomic"
)

// TestWriteFileReplaces verifies that WriteFile creates the destination
// when absent and replaces it when present.
func TestWriteFileReplaces(t *testing.T) {
	t.Parallel()
	files := afero.NewMemMapFs()
	if err := atomic.WriteFile(files, "/data/a.txt", []byte("first"), 0o600); err != nil {
		t.Fatalf("first write: %v", err)
	}
	got, _ := afero.ReadFile(files, "/data/a.txt")
	if string(got) != "first" {
		t.Errorf("read = %q, want %q", got, "first")
	}
	if err := atomic.WriteFile(files, "/data/a.txt", []byte("second"), 0o600); err != nil {
		t.Fatalf("second write: %v", err)
	}
	got, _ = afero.ReadFile(files, "/data/a.txt")
	if string(got) != "second" {
		t.Errorf("read = %q, want %q", got, "second")
	}
}

// TestWriteFileLeavesNoTempOnSuccess verifies the temp sibling is gone
// after a successful write.
func TestWriteFileLeavesNoTempOnSuccess(t *testing.T) {
	t.Parallel()
	files := afero.NewMemMapFs()
	if err := atomic.WriteFile(files, "/data/a.txt", []byte("x"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	var tmpCount int
	_ = afero.Walk(files, "/data", func(path string, info fs.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		if path != "/data/a.txt" {
			tmpCount++
		}
		return nil
	})
	if tmpCount != 0 {
		t.Errorf("unexpected leftover files: %d", tmpCount)
	}
}

