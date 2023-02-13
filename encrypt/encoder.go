package encrypt

// Encoder encodes a file's data.
type Encoder interface {
	Encode(fileName string, fileData []byte) ([]byte, error)
}
