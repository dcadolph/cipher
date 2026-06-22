package cipher

import (
	"context"
	"errors"
	"fmt"

	"github.com/getsops/sops/v3"
	"github.com/getsops/sops/v3/keyservice"

	"github.com/dcadolph/cipher/internal/sopsx"
)

// Encoder encrypts a file's bytes for the given path.
type Encoder interface {
	// Encode returns the encrypted bytes for data identified by path.
	// The path is used for format detection unless the Encoder was
	// configured with a fixed format. Implementations should return
	// ErrAlreadyEncrypted when data already carries sops metadata
	// and ErrEmpty when data has nothing to encrypt.
	Encode(ctx context.Context, path string, data []byte) ([]byte, error)
}

// EncoderFunc adapts a plain function to Encoder.
type EncoderFunc func(ctx context.Context, path string, data []byte) ([]byte, error)

// Encode calls f.
func (f EncoderFunc) Encode(ctx context.Context, path string, data []byte) ([]byte, error) {
	return f(ctx, path, data)
}

// MACMode controls which leaves are covered by the file MAC.
type MACMode int

const (
	// MACInherit defers to the base or parent setting. Zero value.
	// In a router-driven config a rule with MACInherit picks up the
	// Encoder default. In a single-encoder config MACInherit means
	// the sops default (MACOnAll).
	MACInherit MACMode = iota
	// MACOnAll computes the MAC over every leaf, encrypted or not.
	// This is the sops default and the safer choice for tamper
	// detection on the unencrypted parts of the file.
	MACOnAll
	// MACOnEncrypted computes the MAC over encrypted leaves only.
	// Use when you intentionally let plaintext leaves change without
	// invalidating the MAC.
	MACOnEncrypted
)

// EncoderOptions tunes the behavior of an Encoder created with NewEncoderWith.
type EncoderOptions struct {
	// Format, when non-zero, fixes the format for every Encode call.
	// When zero, format is derived from the path on each call.
	Format Format
	// EncryptedRegex restricts encryption to keys matching this regex.
	EncryptedRegex string
	// UnencryptedRegex excludes keys matching this regex from encryption.
	UnencryptedRegex string
	// EncryptedSuffix restricts encryption to keys with this suffix.
	EncryptedSuffix string
	// UnencryptedSuffix excludes keys with this suffix from encryption.
	UnencryptedSuffix string
	// MAC controls which leaves the file MAC covers. Zero value
	// (MACInherit) defers to base in a router or to the sops default.
	// Set MACOnAll or MACOnEncrypted to lock the mode for this Encoder
	// and let router rules override either direction.
	MAC MACMode
	// ShamirThreshold is the number of key groups required to recover
	// the data key. Zero means the sops default.
	ShamirThreshold int
	// KeyServices overrides the default local key service. Empty means
	// a single local key service is used.
	KeyServices []keyservice.KeyServiceClient
	// Cipher overrides the default AES cipher. Nil means aes.NewCipher().
	Cipher sops.Cipher
	// Logger receives encode-time events. Nil uses NopLogger.
	Logger Logger
	// OnEncrypt is called after every successful Encode with the file
	// path, plaintext size, and ciphertext size. Nil is a no-op.
	OnEncrypt func(path string, plaintextBytes, ciphertextBytes int)
	// MaxPlaintextBytes caps the input size. Encode returns an
	// ErrInputTooLarge wrapping ErrEncode when len(data) > MaxPlaintextBytes.
	// Zero means no cap. Sops loads the whole file into memory before
	// emitting, so very large inputs are best detected here.
	MaxPlaintextBytes int
}

// ErrInputTooLarge is returned when an Encoder is asked to encrypt
// input that exceeds EncoderOptions.MaxPlaintextBytes.
var ErrInputTooLarge = errors.New("input exceeds MaxPlaintextBytes")

// NewEncoder returns an Encoder backed by sops using sensible defaults:
// AES cipher, local key service, format inferred from each file's path,
// no key-name filters. Panics if kp is nil.
func NewEncoder(kp KeyProvider) Encoder {
	return NewEncoderWith(kp, EncoderOptions{})
}

// NewEncoderWith returns an Encoder backed by sops using the supplied
// options. Panics if kp is nil.
func NewEncoderWith(kp KeyProvider, opts EncoderOptions) Encoder {
	if kp == nil {
		panic("cipher: NewEncoderWith: KeyProvider required")
	}
	log := opts.Logger
	if log == nil {
		log = NopLogger
	}
	return EncoderFunc(func(ctx context.Context, path string, data []byte) ([]byte, error) {
		log.Debugf("cipher.Encode start: path=%s bytes=%d", path, len(data))
		if opts.MaxPlaintextBytes > 0 && len(data) > opts.MaxPlaintextBytes {
			return nil, fmt.Errorf("%w: %w (limit %d, got %d)",
				ErrEncode, ErrInputTooLarge, opts.MaxPlaintextBytes, len(data))
		}
		groups, err := kp.KeyGroups(ctx)
		if err != nil {
			return nil, fmt.Errorf("%w: key groups: %w", ErrEncode, err)
		}
		if len(groups) == 0 {
			return nil, fmt.Errorf("%w: %w", ErrEncode, ErrNoKeyGroups)
		}

		out, err := sopsx.Encrypt(sopsx.EncryptInput{
			Path:              path,
			Data:              data,
			Format:            opts.Format,
			KeyGroups:         groups,
			KeyServices:       opts.KeyServices,
			Cipher:            opts.Cipher,
			EncryptedRegex:    opts.EncryptedRegex,
			UnencryptedRegex:  opts.UnencryptedRegex,
			EncryptedSuffix:   opts.EncryptedSuffix,
			UnencryptedSuffix: opts.UnencryptedSuffix,
			MACOnlyEncrypted:  opts.MAC == MACOnEncrypted,
			ShamirThreshold:   opts.ShamirThreshold,
		})
		switch {
		case errors.Is(err, sopsx.ErrAlreadyEncrypted):
			log.Warnf("cipher.Encode skip already-encrypted: path=%s", path)
			return nil, ErrAlreadyEncrypted
		case errors.Is(err, sopsx.ErrEmpty):
			log.Warnf("cipher.Encode skip empty: path=%s", path)
			return nil, ErrEmpty
		case errors.Is(err, sopsx.ErrNoKeyGroups):
			return nil, fmt.Errorf("%w: %w", ErrEncode, ErrNoKeyGroups)
		case err != nil:
			return nil, fmt.Errorf("%w: %w", ErrEncode, err)
		}
		log.Debugf("cipher.Encode done: path=%s plaintext=%d ciphertext=%d",
			path, len(data), len(out))
		if opts.OnEncrypt != nil {
			opts.OnEncrypt(path, len(data), len(out))
		}
		return out, nil
	})
}

// ChainEncoders returns an Encoder that feeds the output of each Encoder
// into the next. Useful for composing pre-processing or transformations
// around a sops Encoder.
func ChainEncoders(first Encoder, rest ...Encoder) Encoder {
	if first == nil {
		panic("cipher: ChainEncoders: first encoder required")
	}
	return EncoderFunc(func(ctx context.Context, path string, data []byte) ([]byte, error) {
		out, err := first.Encode(ctx, path, data)
		if err != nil {
			return nil, err
		}
		for _, e := range rest {
			out, err = e.Encode(ctx, path, out)
			if err != nil {
				return nil, err
			}
		}
		return out, nil
	})
}
