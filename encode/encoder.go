package encode

// Encoder encodes a file using an encryption method.
type Encoder interface {
	// Encode encrypts a file.
	Encode(fileName string) ([]byte, error)
}
