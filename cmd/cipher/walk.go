package main

import (
	"fmt"
	"os"
	"regexp"
	"time"

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
	exts         []string
	regex        string
	parallel     int
	backupSuffix string
}

func (w *walkFlags) bind(cmd *cobra.Command) {
	cmd.Flags().StringSliceVar(&w.exts, "ext", []string{"yaml", "yml", "json"},
		"file extensions to match (comma-separated, repeatable)")
	cmd.Flags().StringVar(&w.regex, "regex", "",
		"regex matcher applied to each path (overrides --ext when set)")
	cmd.Flags().IntVar(&w.parallel, "parallel", 1,
		"max files processed concurrently")
	cmd.Flags().StringVar(&w.backupSuffix, "backup-suffix", "",
		"copy each original file to <path><suffix> before overwriting (empty disables backups)")
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
				Parallelism:  wf.parallel,
				BackupSuffix: wf.backupSuffix,
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
				Parallelism:  wf.parallel,
				BackupSuffix: wf.backupSuffix,
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
	var olderThan string
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
			if olderThan != "" {
				ageMatcher, err := olderThanMatcher(olderThan)
				if err != nil {
					return err
				}
				combined := make([]cipher.FileMatcher, 0, len(matchers)+1)
				combined = append(combined, matchers...)
				combined = append(combined, ageMatcher)
				matchers = []cipher.FileMatcher{cipher.MatchAllOf(combined...)}
			}
			opts := cipher.WalkOptions{
				Parallelism:  wf.parallel,
				BackupSuffix: wf.backupSuffix,
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
	cmd.Flags().StringVar(&olderThan, "older-than", "",
		"only rotate files whose sops metadata.LastModified is older than this"+
			" duration (e.g. 90d, 720h)")
	return cmd
}

// olderThanMatcher returns a FileMatcher that admits only files whose
// sops metadata.LastModified is older than the given duration. The
// duration accepts the time.ParseDuration syntax extended with a "d"
// suffix interpreted as 24h.
func olderThanMatcher(spec string) (cipher.FileMatcher, error) {
	d, err := parseDurationWithDays(spec)
	if err != nil {
		return nil, fmt.Errorf("--older-than %q: %w", spec, err)
	}
	cutoff := time.Now().Add(-d)
	return cipher.FileMatcherFunc(func(path string) bool {
		data, err := os.ReadFile(path)
		if err != nil {
			return false
		}
		info, err := cipher.InspectPath(path, data)
		if err != nil {
			return false
		}
		if info.LastModified == "" {
			return false
		}
		t, err := time.Parse(time.RFC3339, info.LastModified)
		if err != nil {
			return false
		}
		return t.Before(cutoff)
	}), nil
}

// parseDurationWithDays accepts time.ParseDuration syntax plus a "d"
// suffix interpreted as 24h. "90d" means 90 * 24h, "12h" means 12h,
// "30m" means 30 minutes. Combined units ("1d12h") are not supported;
// pass them with explicit hours instead.
func parseDurationWithDays(s string) (time.Duration, error) {
	if len(s) > 1 && s[len(s)-1] == 'd' {
		days, err := time.ParseDuration(s[:len(s)-1] + "h")
		if err != nil {
			return 0, fmt.Errorf("invalid day-suffixed duration: %w", err)
		}
		return days * 24, nil
	}
	return time.ParseDuration(s)
}
