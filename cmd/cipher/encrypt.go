package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

// newEncryptCmd returns the `cipher encrypt` subcommand.
func newEncryptCmd() *cobra.Command {
	var inPlace bool
	var output string
	flags := &providerFlags{}
	cmd := &cobra.Command{
		Use:   "encrypt PATH",
		Short: "Encrypt a single file",
		Long: "Encrypt PATH with sops and write the result to PATH (with --in-place),\n" +
			"to --output, or to stdout (default). Use PATH == \"-\" to read stdin.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := args[0]
			enc, err := flags.resolveEncoder(cmd)
			if err != nil {
				return err
			}
			data, err := readPathOrStdin(path)
			if err != nil {
				return err
			}
			out, err := enc.Encode(cmd.Context(), path, data)
			if err != nil {
				return fmt.Errorf("encrypt %q: %w", path, err)
			}
			switch {
			case inPlace && path == "-":
				return fmt.Errorf("--in-place is incompatible with stdin (path \"-\")")
			case inPlace:
				return writePathOrStdout(path, out)
			case output != "":
				return writePathOrStdout(output, out)
			default:
				return writePathOrStdout("-", out)
			}
		},
	}
	flags.bind(cmd.Flags())
	cmd.Flags().BoolVarP(&inPlace, "in-place", "i", false, "write encrypted bytes back to PATH")
	cmd.Flags().StringVarP(&output, "output", "o", "", "write encrypted bytes to this path")
	return cmd
}
