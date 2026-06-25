package age_test

import (
	"context"
	"fmt"
	"log"

	"github.com/dcadolph/cipher"
	"github.com/dcadolph/cipher/age"
)

// ExampleNewProvider builds a Provider from a single age recipient
// and wires it into a cipher.Encoder.
func ExampleNewProvider() {
	kp, err := age.NewProvider("age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p")
	if err != nil {
		log.Fatal(err)
	}
	enc := cipher.NewEncoder(kp)
	_, err = enc.Encode(context.Background(), "secrets.yaml", []byte("foo: bar\n"))
	if err != nil {
		log.Fatal(err)
	}
}

// ExampleGenerateIdentity creates a throwaway age identity. Save
// Secret before discarding the returned value. Recipient is safe to
// publish; Secret unlocks every file encrypted to Recipient.
func ExampleGenerateIdentity() {
	id, err := age.GenerateIdentity()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("save this:", id.Secret) // AGE-SECRET-KEY-1...
	_ = id.Recipient                     // age1...
}

// ExampleMustNewProvider mirrors regexp.MustCompile. Use only at
// package init or in tests where construction failure is a developer
// error.
func ExampleMustNewProvider() {
	kp := age.MustNewProvider("age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p")
	_ = cipher.NewEncoder(kp)
}
