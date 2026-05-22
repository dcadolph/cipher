package main

import (
	"fmt"
	"io"
	"os"

	"github.com/spf13/afero"
)

// readPathOrStdin reads from path, or from stdin when path == "-".
func readPathOrStdin(path string) ([]byte, error) {
	if path == "-" {
		return io.ReadAll(os.Stdin)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %q: %w", path, err)
	}
	return data, nil
}

// writePathOrStdout writes data to path, or to stdout when path == "-".
// Files are written with the original mode if it exists, otherwise 0o600.
func writePathOrStdout(path string, data []byte) error {
	if path == "-" {
		_, err := os.Stdout.Write(data)
		return err
	}
	perm := os.FileMode(0o600)
	if info, err := os.Stat(path); err == nil {
		perm = info.Mode().Perm()
	}
	return os.WriteFile(path, data, perm)
}

// osFs returns the afero filesystem used by walk commands. Centralized
// so future tests can substitute MemMapFs.
func osFs() afero.Fs { return afero.NewOsFs() }
