package cipher

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"

	"github.com/getsops/sops/v3/keyservice"
	"github.com/spf13/afero"

	"github.com/dcadolph/cipher/internal/atomic"
	"github.com/dcadolph/cipher/internal/sopsx"
)

// EditOptions tunes Edit behavior.
type EditOptions struct {
	// BackupSuffix, when non-empty, copies the encrypted original to
	// <path><suffix> before overwriting it. The backup is retained
	// after success so callers can revert or diff.
	BackupSuffix string
}

// Edit reads path from files, decrypts the contents with dec, invokes
// fn on the plaintext, re-encrypts the result with enc, and writes it
// back to the same path atomically.
//
// If fn returns the same bytes (by value), no write occurs and Edit
// returns nil. If fn returns an error, the file is left untouched and
// that error is returned wrapped.
//
// Atomicity: the encrypted bytes are written to a sibling temp file
// which is then renamed into place. On any failure the destination
// remains as it was before the call.
//
// Security: Edit hands plaintext bytes to fn. The caller is
// responsible for not leaking those bytes outside its own memory.
// In particular, callers that materialize plaintext on disk (the
// cipher CLI's edit verb does this for $EDITOR) must use a private
// temp directory (mode 0700) plus restrictive file mode (0600) and
// clean up on exit. The current Edit implementation never writes
// plaintext to disk itself.
//
// Semantic equality: Edit decides "did anything change" by
// bytes.Equal of plaintext and fn's return value. A YAML reformat
// that is semantically identical (key order, indentation, quoting)
// still triggers a re-encrypt because the bytes differ. If round-
// trip stability matters, ensure fn preserves byte layout.
func Edit(
	ctx context.Context, files afero.Fs, path string,
	enc Encoder, dec Decoder,
	fn func(plaintext []byte) ([]byte, error),
) error {
	return EditWith(ctx, files, path, enc, dec, fn, EditOptions{})
}

// EditWith is Edit with explicit options.
func EditWith(
	ctx context.Context, files afero.Fs, path string,
	enc Encoder, dec Decoder,
	fn func(plaintext []byte) ([]byte, error),
	opts EditOptions,
) error {
	if files == nil {
		panic("cipher: EditWith: filesystem required")
	}
	if enc == nil {
		panic("cipher: EditWith: encoder required")
	}
	if dec == nil {
		panic("cipher: EditWith: decoder required")
	}
	if fn == nil {
		panic("cipher: EditWith: edit function required")
	}

	info, err := files.Stat(path)
	if err != nil {
		return fmt.Errorf("stat %q: %w", path, err)
	}
	original, err := afero.ReadFile(files, path)
	if err != nil {
		return fmt.Errorf("read %q: %w", path, err)
	}

	plaintext, err := dec.Decode(ctx, path, original)
	if err != nil {
		return fmt.Errorf("decode %q: %w", path, err)
	}
	// Zero the decrypted plaintext on every return path. Defense in
	// depth: once the caller's mutator has run and we have ciphertext
	// to write, the plaintext is no longer needed and lingering
	// references in memory increase the window for accidental
	// disclosure through core dumps, swap, or process-memory reads.
	defer clear(plaintext)

	modified, err := fn(plaintext)
	if err != nil {
		return fmt.Errorf("edit %q: %w", path, err)
	}
	// Modified may share storage with plaintext (in-place edit) or be
	// a fresh slice. Either way it now holds the post-edit plaintext
	// which we no longer need once encrypted is computed.
	defer clear(modified)

	if bytes.Equal(plaintext, modified) {
		return nil
	}

	encrypted, err := enc.Encode(ctx, path, modified)
	if err != nil {
		return fmt.Errorf("encode %q: %w", path, err)
	}
	if err := writeBackup(files, path, original, info, opts.BackupSuffix); err != nil {
		return err
	}
	if err := atomic.WriteFile(files, path, encrypted, info.Mode().Perm()); err != nil {
		return err
	}
	return nil
}

// Rotate decrypts data with dec and re-encrypts it with enc. A fresh
// data key is generated, so any compromise of the previous data key
// no longer protects the file. Recipients are reset to whatever enc's
// KeyProvider yields; pass the original Encoder to keep recipients,
// or a different one to switch backends.
func Rotate(
	ctx context.Context, path string, data []byte,
	enc Encoder, dec Decoder,
) ([]byte, error) {
	if enc == nil {
		panic("cipher: Rotate: encoder required")
	}
	if dec == nil {
		panic("cipher: Rotate: decoder required")
	}
	plain, err := dec.Decode(ctx, path, data)
	if err != nil {
		return nil, fmt.Errorf("rotate %q: %w", path, err)
	}
	out, err := enc.Encode(ctx, path, plain)
	if err != nil {
		return nil, fmt.Errorf("rotate %q: %w", path, err)
	}
	return out, nil
}

// RotateWalk applies Rotate to every matching file under root. Files
// that are not encrypted are skipped. Plain files do not cause failure.
func RotateWalk(
	ctx context.Context, files afero.Fs, root string,
	enc Encoder, dec Decoder, matchers []FileMatcher,
) error {
	return RotateWalkWith(ctx, files, root, enc, dec, matchers, WalkOptions{})
}

// RotateWalkWith is RotateWalk with explicit options.
func RotateWalkWith(
	ctx context.Context, files afero.Fs, root string,
	enc Encoder, dec Decoder, matchers []FileMatcher, opts WalkOptions,
) error {
	if files == nil {
		panic("cipher: RotateWalkWith: filesystem required")
	}
	if enc == nil {
		panic("cipher: RotateWalkWith: encoder required")
	}
	if dec == nil {
		panic("cipher: RotateWalkWith: decoder required")
	}
	serializeCallbacks(&opts)
	return runWalk(ctx, files, root, matchers, opts,
		func(ctx context.Context, fs afero.Fs, path string, info fs.FileInfo) error {
			data, err := afero.ReadFile(fs, path)
			if err != nil {
				return fmt.Errorf("read %q: %w", path, err)
			}
			out, err := Rotate(ctx, path, data, enc, dec)
			switch {
			case errors.Is(err, ErrNotEncrypted):
				notify(opts.OnSkip, path, ErrNotEncrypted)
				return nil
			case err != nil:
				return err
			}
			if err := writeBackup(fs, path, data, info, opts.BackupSuffix); err != nil {
				return err
			}
			if err := atomic.WriteFile(fs, path, out, info.Mode().Perm()); err != nil {
				return err
			}
			notify(opts.OnFile, path, len(out))
			return nil
		})
}

// AddRecipientMode controls how AddRecipient merges new keys into an
// existing file's metadata.
type AddRecipientMode int

const (
	// AddRecipientFlatten merges all new keys into the file's first
	// existing key group, creating one if none exist. The file remains
	// decryptable by any single recipient.
	AddRecipientFlatten AddRecipientMode = iota
	// AddRecipientAsGroups appends the new key groups as additional
	// groups. With Shamir-threshold defaults this turns the file into
	// a multi-group secret requiring multiple groups to decrypt.
	AddRecipientAsGroups
)

// AddRecipientOptions tunes AddRecipient behavior.
type AddRecipientOptions struct {
	// Mode controls how the KeyProvider's groups are merged into the
	// file's existing key groups. The zero value flattens.
	Mode AddRecipientMode
	// Format, when non-zero, fixes the sops format. When zero, format
	// is derived from path.
	Format Format
	// KeyServices overrides the default local key service.
	KeyServices []keyservice.KeyServiceClient
	// DecryptionOrder controls which key types are tried first when
	// unwrapping the data key. Empty means sops.DefaultDecryptionOrder.
	DecryptionOrder []string
	// MaxCiphertextBytes is the maximum allowed input size in bytes.
	// Zero means no limit. Returns ErrTooLarge when exceeded.
	MaxCiphertextBytes int
}

// AddRecipient appends the keys from add to the file's key groups
// (flattening into the first group by default) and re-wraps the data
// key for all recipients. The payload ciphertext is unchanged. The
// caller must hold an identity for at least one existing recipient so
// the data key can be unwrapped.
func AddRecipient(
	ctx context.Context, path string, data []byte,
	add KeyProvider, opts DecoderOptions,
) ([]byte, error) {
	return AddRecipientWith(ctx, path, data, add, AddRecipientOptions{
		Format:          opts.Format,
		KeyServices:     opts.KeyServices,
		DecryptionOrder: opts.DecryptionOrder,
	})
}

// AddRecipientWith is AddRecipient with explicit options, including
// Mode to control flatten vs. as-groups merge.
func AddRecipientWith(
	ctx context.Context, path string, data []byte,
	add KeyProvider, opts AddRecipientOptions,
) ([]byte, error) {
	if add == nil {
		panic("cipher: AddRecipient: KeyProvider required")
	}
	groups, err := add.KeyGroups(ctx)
	if err != nil {
		return nil, fmt.Errorf("AddRecipient: key groups: %w", err)
	}
	if len(groups) == 0 {
		return nil, fmt.Errorf("AddRecipient: %w", ErrNoKeyGroups)
	}
	out, err := sopsx.AddRecipient(sopsx.AddRecipientInput{
		Path:               path,
		Data:               data,
		Format:             opts.Format,
		NewGroups:          groups,
		Mode:               sopsx.AddRecipientMode(opts.Mode),
		KeyServices:        opts.KeyServices,
		DecryptionOrder:    opts.DecryptionOrder,
		MaxCiphertextBytes: opts.MaxCiphertextBytes,
	})
	switch {
	case errors.Is(err, sopsx.ErrNotEncrypted):
		return nil, ErrNotEncrypted
	case errors.Is(err, sopsx.ErrTooLarge):
		return nil, ErrTooLarge
	case err != nil:
		return nil, fmt.Errorf("AddRecipient: %w", err)
	}
	return out, nil
}

// RemoveRecipientOptions tunes RemoveRecipient behavior.
type RemoveRecipientOptions struct {
	// AllowOrphan, when true, permits removal that would leave the file
	// with zero remaining master keys. The resulting file is
	// undecryptable forever. Required to make data destruction explicit.
	AllowOrphan bool
	// Format, when non-zero, fixes the sops format. When zero, format
	// is derived from path.
	Format Format
	// MaxCiphertextBytes is the maximum allowed input size in bytes.
	// Zero means no limit. Returns ErrTooLarge when exceeded.
	MaxCiphertextBytes int
}

// RemoveRecipient drops master keys from the file's key groups whose
// ToString() identifier matches an entry in identifiers. The payload
// is not decrypted; this is a metadata-only edit. Returns
// ErrOrphanRecipient if removing the supplied identifiers would leave
// the file with zero recipients.
//
// This operation does not perform any network or cancellable work, so
// it intentionally does not take a context.Context. Wrap the call in
// your own context handling if cancellation matters.
func RemoveRecipient(
	path string, data []byte, identifiers ...string,
) ([]byte, error) {
	return RemoveRecipientWith(path, data, identifiers, RemoveRecipientOptions{})
}

// RemoveRecipientWith is RemoveRecipient with explicit options.
// Setting opts.AllowOrphan permits removal of the last remaining
// recipient, which makes the file undecryptable forever.
func RemoveRecipientWith(
	path string, data []byte,
	identifiers []string, opts RemoveRecipientOptions,
) ([]byte, error) {
	if len(identifiers) == 0 {
		return nil, fmt.Errorf("RemoveRecipient: at least one identifier required")
	}
	out, err := sopsx.RemoveRecipient(sopsx.RemoveRecipientInput{
		Path:               path,
		Data:               data,
		Format:             opts.Format,
		Identifiers:        identifiers,
		DropEmptyGroups:    true,
		AllowOrphan:        opts.AllowOrphan,
		MaxCiphertextBytes: opts.MaxCiphertextBytes,
	})
	switch {
	case errors.Is(err, sopsx.ErrNotEncrypted):
		return nil, ErrNotEncrypted
	case errors.Is(err, sopsx.ErrOrphanRecipient):
		return nil, ErrOrphanRecipient
	case errors.Is(err, sopsx.ErrTooLarge):
		return nil, ErrTooLarge
	case err != nil:
		return nil, fmt.Errorf("RemoveRecipient: %w", err)
	}
	return out, nil
}
