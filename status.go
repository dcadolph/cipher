package cipher

import "github.com/dcadolph/cipher/internal/sopsx"

// IsEncrypted reports whether data is a sops-encrypted file of the given
// format. Returns false for unencrypted data and for data that fails
// to parse as the format's encrypted shape.
func IsEncrypted(data []byte, format Format) bool {
	return sopsx.IsEncrypted(data, format)
}

// IsEncryptedPath reports whether data is sops-encrypted using the format
// inferred from path.
func IsEncryptedPath(path string, data []byte) bool {
	return sopsx.IsEncrypted(data, FormatForPath(path))
}
