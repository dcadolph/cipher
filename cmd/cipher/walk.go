package main

import (
	"fmt"
	"regexp"

	"github.com/spf13/cobra"

	"github.com/dcadolph/cipher"
)

// newWalkCmd returns the `cipher walk` command group with encrypt,
// decrypt, and rotate subcommands.
func newWalkCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "walk",
		Short: "Walk a directory and apply an operation to every match",
	}
	root.AddCommand(newWalkEncryptCmd(), newWalkDecryptCmd(), newWalkRotateCmd())
	return root
}

// walkFlags holds shared walk-time flags.
type walkFlags struct {
	exts     []string
	regex    string
	parallel int
}

func (w *walkFlags) bind(cmd *cobra.Command) {
	cmd.Flags().StringSliceVar(&w.exts, "ext", []string{"yaml", "yml", "json"},
		"file extensions to match (comma-separated, repeatable)")
	cmd.Flags().StringVar(&w.regex, "regex", "",
		"regex matcher applied to each path (overrides --ext when set)")
	cmd.Flags().IntVar(&w.parallel, "parallel", 1,
		"max files processed concurrently")
}

func (w *walkFlags) matchers() ([]cipher.FileMatcher, error) {
	if w.regex != "" {
		re, err := regexp.Compile(w.regex)
		if err != nil {
			return nil, fmt.Errorf("--regex: %w", err)
		}
		return []cipher.FileMatcher{cipher.MatchRegex(re)}, nil
	}
	return []cipher.FileMatcher{cipher.MatchExt(w.exts...)}, nil
}

// newWalkEncryptCmd: `cipher walk encrypt ROOT`.
func newWalkEncryptCmd() *cobra.Command {
	wf := &walkFlags{}
	pf := &providerFlags{}
	cmd := &cobra.Command{
		Use:   "encrypt ROOT",
		Short: "Encrypt every matching file under ROOT",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			enc, err := pf.resolveEncoder(cmd)
			if err != nil {
				return err
			}
			matchers, err := wf.matchers()
			if err != nil {
				return err
			}
			opts := cipher.WalkOptions{
				Parallelism: wf.parallel,
				OnFile: func(p string, n int) {
					fmt.Fprintf(cmd.OutOrStdout(), "encrypted %s (%d bytes)\n", p, n)
				},
				OnSkip: func(p string, reason error) {
					fmt.Fprintf(cmd.ErrOrStderr(), "skipped %s: %v\n", p, reason)
				},
			}
			return cipher.EncodeWalkWith(cmd.Context(), osFs(), args[0], enc, matchers, opts)
		},
	}
	wf.bind(cmd)
	pf.bind(cmd.Flags())
	return cmd
}

// newWalkDecryptCmd: `cipher walk decrypt ROOT`.
func newWalkDecryptCmd() *cobra.Command {
	wf := &walkFlags{}
	cmd := &cobra.Command{
		Use:   "decrypt ROOT",
		Short: "Decrypt every matching file under ROOT",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			matchers, err := wf.matchers()
			if err != nil {
				return err
			}
			opts := cipher.WalkOptions{
				Parallelism: wf.parallel,
				OnFile: func(p string, n int) {
					fmt.Fprintf(cmd.OutOrStdout(), "decrypted %s (%d bytes)\n", p, n)
				},
				OnSkip: func(p string, reason error) {
					fmt.Fprintf(cmd.ErrOrStderr(), "skipped %s: %v\n", p, reason)
				},
			}
			return cipher.DecodeWalkWith(
				cmd.Context(), osFs(), args[0],
				cipher.NewDecoder(), matchers, opts,
			)
		},
	}
	wf.bind(cmd)
	return cmd
}

// newWalkRotateCmd: `cipher walk rotate ROOT`.
func newWalkRotateCmd() *cobra.Command {
	wf := &walkFlags{}
	pf := &providerFlags{}
	cmd := &cobra.Command{
		Use:   "rotate ROOT",
		Short: "Rotate every matching file under ROOT",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			enc, err := pf.resolveEncoder(cmd)
			if err != nil {
				return err
			}
			matchers, err := wf.matchers()
			if err != nil {
				return err
			}
			opts := cipher.WalkOptions{
				Parallelism: wf.parallel,
				OnFile: func(p string, n int) {
					fmt.Fprintf(cmd.OutOrStdout(), "rotated %s (%d bytes)\n", p, n)
				},
				OnSkip: func(p string, reason error) {
					fmt.Fprintf(cmd.ErrOrStderr(), "skipped %s: %v\n", p, reason)
				},
			}
			return cipher.RotateWalkWith(
				cmd.Context(), osFs(), args[0],
				enc, cipher.NewDecoder(), matchers, opts,
			)
		},
	}
	wf.bind(cmd)
	pf.bind(cmd.Flags())
	return cmd
}
