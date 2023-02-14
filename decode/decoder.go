package decode

// Decoder decodes a file using an decryption method.
type Decoder interface {
	// Decode decodes an encrypted file.
	Decode(fileName string) ([]byte, error)
}
