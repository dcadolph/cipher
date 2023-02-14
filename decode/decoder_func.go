package decode

// DecoderFunc implements Decoder to allow function literals to be used in place of struct-derived
// objects that implement Decoder.
type DecoderFunc func(fileName string) ([]byte, error)

// Decode merely calls the receiver to implement the Decoder interface.
func (f DecoderFunc) Decode(fileName string) ([]byte, error) {
	return f(fileName)
}
