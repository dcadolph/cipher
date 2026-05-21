package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/spf13/afero"
	"github.com/spf13/cobra"

	"github.com/dcadolph/cipher"
)

// newEditCmd returns the `cipher edit` subcommand. It decrypts PATH to
// a temp file, opens it in $EDITOR (or --cmd), then re-encrypts and
// writes the result atomically.
func newEditCmd() *cobra.Command {
	var editor string
	flags := &providerFlags{}
	cmd := &cobra.Command{
		Use:   "edit PATH",
		Short: "Interactively edit a sops-encrypted file",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := args[0]
			enc, err := flags.resolveEncoder(cmd)
			if err != nil {
				return err
			}
			dec := cipher.NewDecoder()
			ed := pickEditor(editor)
			return cipher.Edit(cmd.Context(), afero.NewOsFs(), path, enc, dec,
				func(plain []byte) ([]byte, error) {
					return launchEditor(ed, path, plain)
				},
			)
		},
	}
	flags.bind(cmd.Flags())
	cmd.Flags().StringVar(&editor, "cmd", "",
		"editor command (default $EDITOR, then $VISUAL, then vi)")
	return cmd
}

// pickEditor resolves the editor command to launch.
func pickEditor(override string) string {
	if override != "" {
		return override
	}
	if e := os.Getenv("EDITOR"); e != "" {
		return e
	}
	if e := os.Getenv("VISUAL"); e != "" {
		return e
	}
	return "vi"
}

// launchEditor writes plain to a temp file, runs the editor on it, and
// returns the file's contents after the editor exits.
func launchEditor(editorCmd, originalPath string, plain []byte) ([]byte, error) {
	dir, err := os.MkdirTemp("", "cipher-edit-")
	if err != nil {
		return nil, fmt.Errorf("temp dir: %w", err)
	}
	defer func() { _ = os.RemoveAll(dir) }()

	tmpPath := filepath.Join(dir, filepath.Base(originalPath))
	if err := os.WriteFile(tmpPath, plain, 0o600); err != nil {
		return nil, fmt.Errorf("write tmp: %w", err)
	}

	c := exec.Command("sh", "-c", editorCmd+" "+shellQuote(tmpPath))
	c.Stdin = os.Stdin
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr
	if err := c.Run(); err != nil {
		return nil, fmt.Errorf("editor exited: %w", err)
	}

	return os.ReadFile(tmpPath)
}

// shellQuote produces a single-quoted form of s safe for /bin/sh.
func shellQuote(s string) string {
	out := []byte{'\''}
	for i := 0; i < len(s); i++ {
		if s[i] == '\'' {
			out = append(out, '\'', '\\', '\'', '\'')
			continue
		}
		out = append(out, s[i])
	}
	out = append(out, '\'')
	return string(out)
}
