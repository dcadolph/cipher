// Package atomic provides best-effort atomic file writes on top of an
// afero.Fs. Writes go to a sibling temp file which is then renamed
// into place. Failures leave the temp file behind for diagnosis and
// leave the destination unchanged.
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
// Returns the error from the first failing step; on failure the temp
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
	if err := f.Close(); err != nil {
		_ = files.Remove(tmpPath)
		return fmt.Errorf("atomic: close temp %q: %w", tmpPath, err)
	}
	if err := files.Rename(tmpPath, path); err != nil {
		_ = files.Remove(tmpPath)
		return fmt.Errorf("atomic: rename %q -> %q: %w", tmpPath, path, err)
	}
	return nil
}

// randSuffix returns 16 hex chars of random data for temp file naming.
func randSuffix() (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}
