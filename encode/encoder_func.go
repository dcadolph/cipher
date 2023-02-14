package encode

// EncoderFunc implements Encoder to allow function literals to be used in place of struct-derived
// objects that implement Encoder.
type EncoderFunc func(fileName string) ([]byte, error)

// Encode merely calls the receiver to implement the Encoder interface.
func (f EncoderFunc) Encode(fileName string) ([]byte, error) {
	return f(fileName)
}
