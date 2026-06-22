// Package atomic provides best-effort atomic file writes on top of an
// afero.Fs. Writes go to a sibling temp file which is then renamed
// into place. Failures leave the temp file behind for diagnosis and
// leave the destination unchanged.
//
// # Durability
//
// WriteFile calls Sync on the temp file before closing and Sync on
// the parent directory after renaming. On POSIX filesystems backed by
// afero.OsFs this means data and the rename are durable when WriteFile
// returns. Some afero adapters (in-memory, network) silently no-op on
// Sync; on those backends durability is whatever the adapter provides.
// Some Windows configurations do not allow Sync on directory handles
// and the dir sync is skipped with no error returned.
package atomic

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/spf13/afero"
)

// WriteFile writes data to path with the given permission bits using a
// temp-file-and-rename strategy. The temp file lives in the same
// directory as path so the rename stays inside one filesystem.
//
// Returns the error from the first failing step. On failure the temp
// file is removed (best effort) and the destination is left untouched.
func WriteFile(files afero.Fs, path string, data []byte, perm fs.FileMode) error {
	dir := filepath.Dir(path)
	base := filepath.Base(path)
	tmpName, err := randSuffix()
	if err != nil {
		return fmt.Errorf("atomic: random suffix: %w", err)
	}
	tmpPath := filepath.Join(dir, "."+base+".tmp."+tmpName)

	f, err := files.OpenFile(tmpPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		return fmt.Errorf("atomic: open temp %q: %w", tmpPath, err)
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = files.Remove(tmpPath)
		return fmt.Errorf("atomic: write temp %q: %w", tmpPath, err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = files.Remove(tmpPath)
		return fmt.Errorf("atomic: sync temp %q: %w", tmpPath, err)
	}
	if err := f.Close(); err != nil {
		_ = files.Remove(tmpPath)
		return fmt.Errorf("atomic: close temp %q: %w", tmpPath, err)
	}
	if err := files.Rename(tmpPath, path); err != nil {
		_ = files.Remove(tmpPath)
		return fmt.Errorf("atomic: rename %q -> %q: %w", tmpPath, path, err)
	}
	syncDir(files, dir)
	return nil
}

// syncDir opens dir and calls Sync so that the rename made above is
// durable on POSIX filesystems. Failures are intentionally swallowed
// because not every afero.Fs supports opening a directory or syncing
// it (notably in-memory adapters and some Windows configurations).
// On those backends the rename is already as durable as the adapter
// allows. Returning an error here would surface implementation
// details that callers cannot act on.
func syncDir(files afero.Fs, dir string) {
	d, err := files.Open(dir)
	if err != nil {
		return
	}
	defer func() { _ = d.Close() }()
	_ = d.Sync()
}

// randSuffix returns 16 hex chars of random data for temp file naming.
func randSuffix() (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}
