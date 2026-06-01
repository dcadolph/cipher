package main

import (
	"fmt"
	"os"

	"github.com/spf13/afero"
	"github.com/spf13/cobra"

	"github.com/dcadolph/cipher"
	"github.com/dcadolph/cipher/sopsconfig"
)

// newFixCmd returns the `cipher fix ROOT` subcommand. It walks ROOT,
// finds files that match a creation rule in the project's .sops.yaml
// but are still in plaintext, and encrypts them in place using the
// rule's recipients. Already-encrypted files are skipped.
func newFixCmd() *cobra.Command {
	var configPath, backupSuffix string
	var parallel int
	cmd := &cobra.Command{
		Use:   "fix ROOT",
		Short: "Encrypt every plaintext file under ROOT that should be encrypted per .sops.yaml",
		Long: "Walks ROOT, runs each file against the project's .sops.yaml creation\n" +
			"rules, and encrypts any matching files that are still plaintext.\n" +
			"Use this to repair a tree where a .sops.yaml rule was added after\n" +
			"plaintext files were committed.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			root := args[0]
			cfg, err := loadSopsConfig(configPath)
			if err != nil {
				return err
			}
			router := cfg.Router(nil)
			enc := cipher.NewRoutedEncoder(router, cipher.EncoderOptions{})

			matcher := cipher.FileMatcherFunc(func(path string) bool {
				ok, err := cfg.MatchesAnyRule(path, nil)
				return err == nil && ok
			})

			opts := cipher.WalkOptions{
				Parallelism:  parallel,
				BackupSuffix: backupSuffix,
				OnFile: func(p string, n int) {
					fmt.Fprintf(cmd.OutOrStdout(), "fixed %s (%d bytes)\n", p, n)
				},
				OnSkip: func(p string, reason error) {
					fmt.Fprintf(cmd.ErrOrStderr(), "skipped %s: %v\n", p, reason)
				},
			}
			return cipher.EncodeWalkWith(
				cmd.Context(), afero.NewOsFs(), root, enc,
				[]cipher.FileMatcher{matcher}, opts,
			)
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "",
		"path to .sops.yaml or directory containing it (default: search upward from ROOT)")
	cmd.Flags().StringVar(&backupSuffix, "backup-suffix", "",
		"copy each original file to <path><suffix> before overwriting")
	cmd.Flags().IntVar(&parallel, "parallel", 1, "max files processed concurrently")
	return cmd
}

// loadSopsConfig returns the resolved sops config from configPath, or
// by searching upward from the current working directory when
// configPath is empty.
func loadSopsConfig(configPath string) (*sopsconfig.Config, error) {
	if configPath != "" {
		return sopsconfig.Load(configPath)
	}
	cwd, err := os.Getwd()
	if err != nil {
		return nil, err
	}
	return sopsconfig.LoadFromDir(cwd)
}
