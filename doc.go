// Package cipher is a Go library for sops-based encryption and
// decryption of files, directories, and in-memory data. It wraps the
// underlying getsops/sops library so callers do not have to assemble
// sops Trees, key groups, stores, ciphers, and key services by hand.
//
// # Why
//
// Sops ships a stable Go API for decryption only ([decrypt.File] and
// [decrypt.Data]). Programmatic encryption is not part of that surface.
// Encrypting from Go today means assembling a [sops.Tree], building
// [sops.KeyGroup] values, picking a [sops.Cipher], calling internal
// helpers under cmd/sops/common, and emitting through a per-format
// store. cipher collapses that boilerplate into small interfaces with
// sensible defaults.
//
// # Core interfaces
//
// Four single-method interfaces drive everything. Each has a matching
// Func adapter in the http.HandlerFunc style, so a plain function can
// satisfy the interface without a wrapping struct.
//
//   - [Encoder] encrypts a file's bytes for a given path.
//   - [Decoder] decrypts a file's bytes for a given path.
//   - [KeyProvider] returns the sops key groups used by an Encoder.
//   - [FileMatcher] decides whether a path participates in a walk.
//
// A fifth interface, [Router], composes a [KeyProvider] selection from
// a path. It is consulted on every Encode call by encoders built with
// [NewRoutedEncoder]. The [sopsconfig] subpackage produces a Router
// from a project's .sops.yaml.
//
// # Quick start
//
//	import (
//	    "context"
//	    "github.com/dcadolph/cipher"
//	    "github.com/dcadolph/cipher/age"
//	)
//
//	ctx := context.Background()
//	enc := cipher.NewEncoder(age.NewProvider("age1qyqsz..."))
//	ciphertext, err := enc.Encode(ctx, "secrets.yaml", []byte("foo: bar\n"))
//	if err != nil { /* ... */ }
//
//	dec := cipher.NewDecoder()
//	plain, err := dec.Decode(ctx, "secrets.yaml", ciphertext)
//
// Decryption identities come from the standard sops sources
// (SOPS_AGE_KEY, AWS credentials, GCP application-default, Azure
// environment, Vault token, GPG keyrings). The same environment that
// drives the sops binary works here.
//
// # Backends
//
// Each backend lives in its own subpackage and implements [KeyProvider]:
//
//   - cipher/age: age recipients (X25519, hybrid, plugin, SSH)
//   - cipher/kms: AWS KMS
//   - cipher/gcpkms: GCP KMS
//   - cipher/vault: HashiCorp Vault Transit
//   - cipher/azkv: Azure Key Vault
//   - cipher/pgp: GPG fingerprints
//
// Compose them with [MergeProviders] (all keys into one group, any
// recipient decrypts) or [ChainKeyProviders] (each provider stays its
// own group, useful with [EncoderOptions.ShamirThreshold]).
//
// # Walking a directory
//
// [EncodeWalk], [DecodeWalk], and [RotateWalk] apply an Encoder, Decoder,
// or rotation to every matching file under a root directory on any
// [afero.Fs]. The walker supports bounded parallelism via
// [WalkOptions.Parallelism], atomic temp-file-plus-rename writes,
// optional backups via [WalkOptions.BackupSuffix], and OnFile / OnSkip
// callbacks.
//
// Skips are first-class. Already-encrypted files on encode and plain
// files on decode are not failures; they fire OnSkip with the relevant
// sentinel error ([ErrAlreadyEncrypted] or [ErrNotEncrypted]).
//
// # Operations beyond a single Encode
//
//   - [Edit] decrypts, calls a mutator, re-encrypts, and writes atomically.
//   - [Rotate] decrypts and re-encrypts with a fresh data key.
//   - [AddRecipient] inserts new keys into the file's key groups without
//     decrypting the payload.
//   - [RemoveRecipient] drops master keys by identifier without
//     decrypting the payload.
//   - [Inspect] and [InspectPath] read recipient metadata without
//     decryption.
//   - [DiffRecipients] and [DiffRecipientsPath] compute added and
//     removed recipients between two versions of the same secret.
//
// # Errors
//
// Sentinel errors for use with [errors.Is]:
//
//   - [ErrEncode] and [ErrDecode] wrap any encode or decode failure.
//   - [ErrAlreadyEncrypted] is returned when input already carries sops
//     metadata.
//   - [ErrNotEncrypted] is returned when input is plain.
//   - [ErrEmpty] is returned when input has no encryptable branches.
//   - [ErrNoKeyGroups] is returned when an encoder has no key groups.
//   - [ErrUnsupportedFormat] is returned for formats this library does
//     not handle.
//   - [ErrNoMatchingRule] is returned when a Router cannot match the
//     path.
//   - [ErrInputTooLarge] is returned when [EncoderOptions.MaxPlaintextBytes]
//     is exceeded.
//
// # Formats
//
// Cipher passes through every format sops supports: YAML, JSON, INI,
// dotenv, and binary. [Format], [FormatForPath], and [IsEncrypted] are
// stable aliases so callers do not need to import sops sub-packages
// for common operations.
//
// # Related subpackages
//
//   - cipher/sopsconfig parses .sops.yaml and returns a [Router].
//   - cipher/precommit detects unencrypted files that .sops.yaml says
//     should be encrypted.
//   - cipher/httpmw provides net/http middleware that decrypts inbound
//     bodies or encrypts outbound bodies.
//   - cipher/otelcipher wraps Encoder, Decoder, and KeyProvider with
//     OpenTelemetry spans.
//   - cipher/ciphertest exposes test helpers for code that uses cipher.
package cipher
