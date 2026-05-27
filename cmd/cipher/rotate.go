package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/dcadolph/cipher"
)

// newRotateCmd returns the `cipher rotate` subcommand. Rotation
// regenerates the data key and re-encrypts the payload using the same
// recipients (or a different set, if recipient flags are supplied).
func newRotateCmd() *cobra.Command {
	flags := &providerFlags{}
	cmd := &cobra.Command{
		Use:   "rotate PATH [PATH...]",
		Short: "Rotate the data key (and optionally recipients) for one or more files",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			enc, err := flags.resolveEncoder(cmd)
			if err != nil {
				return err
			}
			dec := cipher.NewDecoder()
			for _, path := range args {
				data, err := readPathOrStdin(path)
				if err != nil {
					return err
				}
				out, err := cipher.Rotate(cmd.Context(), path, data, enc, dec)
				if err != nil {
					return fmt.Errorf("rotate %q: %w", path, err)
				}
				if err := writePathOrStdout(path, out); err != nil {
					return err
				}
			}
			return nil
		},
	}
	flags.bind(cmd.Flags())
	return cmd
}
