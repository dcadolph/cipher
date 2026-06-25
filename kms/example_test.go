package kms_test

import (
	"context"
	"log"

	"github.com/dcadolph/cipher"
	"github.com/dcadolph/cipher/kms"
)

// ExampleNewProvider builds a kms Provider from one or more ARNs
// using the default aws credential chain.
func ExampleNewProvider() {
	kp, err := kms.NewProvider("arn:aws:kms:us-east-1:111122223333:key/abcd1234-ef56-7890-abcd-ef1234567890")
	if err != nil {
		log.Fatal(err)
	}
	enc := cipher.NewEncoder(kp)
	_, err = enc.Encode(context.Background(), "secrets.yaml", []byte("foo: bar\n"))
	if err != nil {
		log.Fatal(err)
	}
}

// ExampleNewProviderWith adds an encryption context and an aws
// profile. The same encryption context must be available at
// decryption time.
func ExampleNewProviderWith() {
	opts := kms.ProviderOptions{
		EncryptionContext: map[string]string{"env": "prod"},
		Profile:           "cipher-ci",
	}
	kp, err := kms.NewProviderWith(
		opts,
		"arn:aws:kms:us-east-1:111122223333:key/abcd1234-ef56-7890-abcd-ef1234567890",
	)
	if err != nil {
		log.Fatal(err)
	}
	_ = cipher.NewEncoder(kp)
}
