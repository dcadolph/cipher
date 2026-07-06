package atomic_test

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

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

// TestWriteFileEmpty writes a zero-byte file and verifies it lands.
func TestWriteFileEmpty(t *testing.T) {
	t.Parallel()
	files := afero.NewMemMapFs()
	if err := atomic.WriteFile(files, "/data/empty.txt", []byte{}, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, _ := afero.ReadFile(files, "/data/empty.txt")
	if len(got) != 0 {
		t.Errorf("read len = %d, want 0", len(got))
	}
}

// TestWriteFileLarge writes a multi-megabyte file and verifies byte fidelity.
func TestWriteFileLarge(t *testing.T) {
	t.Parallel()
	files := afero.NewMemMapFs()
	data := make([]byte, 4*1024*1024)
	for i := range data {
		data[i] = byte(i % 251)
	}
	if err := atomic.WriteFile(files, "/data/big.bin", data, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, _ := afero.ReadFile(files, "/data/big.bin")
	if len(got) != len(data) {
		t.Fatalf("read len = %d, want %d", len(got), len(data))
	}
	for i, b := range got {
		if b != data[i] {
			t.Fatalf("byte %d = %d, want %d", i, b, data[i])
		}
	}
}

// TestWriteFilePreservesContentOnOpenFailure verifies the destination is
// untouched when the temp file cannot be opened.
func TestWriteFilePreservesContentOnOpenFailure(t *testing.T) {
	t.Parallel()
	base := afero.NewMemMapFs()
	const path = "/data/keep.txt"
	if err := afero.WriteFile(base, path, []byte("original"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	files := &openFailFs{Fs: base}

	err := atomic.WriteFile(files, path, []byte("replacement"), 0o600)
	if err == nil {
		t.Fatal("expected open failure, got nil")
	}
	if !strings.Contains(err.Error(), "open temp") {
		t.Errorf("err = %v, want substring %q", err, "open temp")
	}
	got, _ := afero.ReadFile(base, path)
	if string(got) != "original" {
		t.Errorf("destination clobbered: %q", got)
	}
}

// TestWriteFilePreservesContentOnRenameFailure verifies that a rename
// error leaves the original file in place and cleans up the temp file.
func TestWriteFilePreservesContentOnRenameFailure(t *testing.T) {
	t.Parallel()
	base := afero.NewMemMapFs()
	const path = "/data/keep.txt"
	if err := afero.WriteFile(base, path, []byte("original"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	files := &renameFailFs{Fs: base}

	err := atomic.WriteFile(files, path, []byte("replacement"), 0o600)
	if err == nil {
		t.Fatal("expected rename failure, got nil")
	}
	if !strings.Contains(err.Error(), "rename") {
		t.Errorf("err = %v, want substring %q", err, "rename")
	}
	got, _ := afero.ReadFile(base, path)
	if string(got) != "original" {
		t.Errorf("destination clobbered: %q", got)
	}
	var tmpCount int
	_ = afero.Walk(base, "/data", func(p string, info fs.FileInfo, walkErr error) error {
		if walkErr != nil || info.IsDir() || p == path {
			return nil
		}
		tmpCount++
		return nil
	})
	if tmpCount != 0 {
		t.Errorf("leftover temp files: %d", tmpCount)
	}
}

// TestWriteFilePreservesContentOnWriteFailure verifies that a write
// error during the temp body leaves the destination untouched.
func TestWriteFilePreservesContentOnWriteFailure(t *testing.T) {
	t.Parallel()
	base := afero.NewMemMapFs()
	const path = "/data/keep.txt"
	if err := afero.WriteFile(base, path, []byte("original"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	files := &writeFailFs{Fs: base}

	err := atomic.WriteFile(files, path, []byte("replacement"), 0o600)
	if err == nil {
		t.Fatal("expected write failure, got nil")
	}
	if !strings.Contains(err.Error(), "write temp") {
		t.Errorf("err = %v, want substring %q", err, "write temp")
	}
	got, _ := afero.ReadFile(base, path)
	if string(got) != "original" {
		t.Errorf("destination clobbered: %q", got)
	}
}

// TestWriteFilePreservesContentOnCloseFailure verifies a close error
// surfaces and the destination is untouched.
func TestWriteFilePreservesContentOnCloseFailure(t *testing.T) {
	t.Parallel()
	base := afero.NewMemMapFs()
	const path = "/data/keep.txt"
	if err := afero.WriteFile(base, path, []byte("original"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	files := &closeFailFs{Fs: base}

	err := atomic.WriteFile(files, path, []byte("replacement"), 0o600)
	if err == nil {
		t.Fatal("expected close failure, got nil")
	}
	if !strings.Contains(err.Error(), "close temp") {
		t.Errorf("err = %v, want substring %q", err, "close temp")
	}
	got, _ := afero.ReadFile(base, path)
	if string(got) != "original" {
		t.Errorf("destination clobbered: %q", got)
	}
}

// TestWriteFilePermissions verifies the destination uses the requested
// permission bits on a real filesystem. Skipped on Windows because file
// modes there work differently.
func TestWriteFilePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file modes differ on windows")
	}
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "perm.txt")
	if err := atomic.WriteFile(afero.NewOsFs(), path, []byte("x"), 0o640); err != nil {
		t.Fatalf("write: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm() != 0o640 {
		t.Errorf("mode = %v, want %v", info.Mode().Perm(), os.FileMode(0o640))
	}
}

// TestWriteFileConcurrent fires many overlapping writers at distinct
// paths and verifies all complete cleanly.
func TestWriteFileConcurrent(t *testing.T) {
	t.Parallel()
	files := afero.NewMemMapFs()
	if err := files.MkdirAll("/data", 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	const workers = 32
	var wg sync.WaitGroup
	errs := make([]error, workers)
	for i := range workers {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			path := "/data/file_" + strconv.Itoa(idx) + ".txt"
			errs[idx] = atomic.WriteFile(files, path, []byte("hello"), 0o600)
		}(i)
	}
	wg.Wait()
	for i, e := range errs {
		if e != nil {
			t.Errorf("writer %d: %v", i, e)
		}
	}
}

// TestWriteFileTimingDoesNotPanic guards against goroutine timing
// regressions in the open/close/rename path. Drives many sequential
// writes under tight timing.
func TestWriteFileTimingDoesNotPanic(t *testing.T) {
	t.Parallel()
	files := afero.NewMemMapFs()
	deadline := time.Now().Add(200 * time.Millisecond)
	count := 0
	for time.Now().Before(deadline) {
		if err := atomic.WriteFile(files, "/d/f.txt", []byte("x"), 0o600); err != nil {
			t.Fatalf("write %d: %v", count, err)
		}
		count++
	}
}

// errStubFile is an afero.File whose Write returns a stub error so the
// temp body write path can be exercised.
type errStubFile struct {
	afero.File
}

// Write returns a sentinel error so the WriteFile temp body fails.
func (errStubFile) Write([]byte) (int, error) { return 0, errors.New("stub write failure") }

// closeStubFile is an afero.File whose Close returns a stub error so the
// post-write close path can be exercised.
type closeStubFile struct {
	afero.File
}

// Close returns a sentinel error so callers see a close failure.
func (closeStubFile) Close() error { return errors.New("stub close failure") }

// closeFailFs returns files that error on Close.
type closeFailFs struct{ afero.Fs }

// OpenFile returns a file whose Close always errors.
func (c *closeFailFs) OpenFile(name string, flag int, perm os.FileMode) (afero.File, error) {
	f, err := c.Fs.OpenFile(name, flag, perm)
	if err != nil {
		return nil, err
	}
	return closeStubFile{File: f}, nil
}

// openFailFs fails OpenFile so the temp file can never be created.
type openFailFs struct{ afero.Fs }

// OpenFile always errors so callers see an open failure.
func (openFailFs) OpenFile(string, int, os.FileMode) (afero.File, error) {
	return nil, errors.New("stub open failure")
}

// renameFailFs fails Rename so the temp file cannot be moved into place.
type renameFailFs struct{ afero.Fs }

// Rename always errors so callers see a rename failure.
func (renameFailFs) Rename(string, string) error { return errors.New("stub rename failure") }

// writeFailFs wraps the underlying Fs but returns an errStubFile from
// OpenFile so Write on the temp file fails.
type writeFailFs struct{ afero.Fs }

// OpenFile returns a file whose Write always errors.
func (w *writeFailFs) OpenFile(name string, flag int, perm os.FileMode) (afero.File, error) {
	f, err := w.Fs.OpenFile(name, flag, perm)
	if err != nil {
		return nil, err
	}
	return errStubFile{File: f}, nil
}
