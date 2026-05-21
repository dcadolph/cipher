// Package cipher is a Go library for sops-based encryption and decryption
// of files, directories, and in-memory data. It wraps the underlying
// getsops/sops library so callers do not have to assemble sops Trees,
// key groups, stores, ciphers, and key services by hand.
//
// The library is organized around four single-method interfaces:
//
//   - Encoder encrypts a file's bytes for a given path.
//   - Decoder decrypts a file's bytes for a given path.
//   - KeyProvider returns the sops key groups used by an Encoder.
//   - FileMatcher decides whether a path participates in a walk.
//
// Each interface has a matching Func type (EncoderFunc, DecoderFunc, etc.)
// in the http.HandlerFunc style, so a plain function can satisfy the
// interface without a wrapping struct.
//
// Concrete KeyProvider implementations live in subpackages
// (cipher/age, etc.). EncodeWalk and DecodeWalk apply an Encoder or
// Decoder to every matching file under a root directory on any afero.Fs.
//
// Format detection, IsEncrypted, and the Format enum are surfaced as
// stable aliases so callers do not need to import sops sub-packages
// for common operations.
package cipher
