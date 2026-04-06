package cipher_test

import (
	"context"
	"fmt"
	"log"

	"github.com/spf13/afero"

	"github.com/dcadolph/cipher"
	cipherage "github.com/dcadolph/cipher/age"
)

// Example demonstrates the common flow: build a KeyProvider, build an
// Encoder, encrypt a single file in memory.
func Example() {
	const recipient = "age1qyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgp..."
	enc := cipher.NewEncoder(cipherage.MustNewProvider(recipient))
	ciphertext, err := enc.Encode(
		context.Background(), "secrets.yaml", []byte("foo: bar\n"),
	)
	if err != nil {
		log.Fatal(err)
	}
	_ = ciphertext
}

// ExampleEncoder shows how to build an Encoder with custom encryption
// options that restrict encryption to keys matching a regex.
func ExampleEncoder() {
	const recipient = "age1qyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgp..."
	enc := cipher.NewEncoderWith(
		cipherage.MustNewProvider(recipient),
		cipher.EncoderOptions{EncryptedRegex: "^secret_"},
	)
	out, err := enc.Encode(
		context.Background(), "x.yaml",
		[]byte("public: visible\nsecret_password: hunter2\n"),
	)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(cipher.IsEncryptedPath("x.yaml", out))
}

// ExampleDecoder shows how to decrypt sops-encrypted bytes. Identity
// resolution follows the standard sops lookup (SOPS_AGE_KEY,
// SOPS_AGE_KEY_FILE, ssh-agent, AWS credentials, etc.).
func ExampleDecoder() {
	dec := cipher.NewDecoder()
	plain, err := dec.Decode(
		context.Background(), "secrets.yaml", []byte("..."),
	)
	if err != nil {
		log.Fatal(err)
	}
	_ = plain
}

// ExampleEncodeWalk walks a directory and encrypts every matching file.
// Already-encrypted files are skipped.
func ExampleEncodeWalk() {
	const recipient = "age1..."
	enc := cipher.NewEncoder(cipherage.MustNewProvider(recipient))
	files := afero.NewOsFs()
	err := cipher.EncodeWalk(
		context.Background(), files, "./secrets", enc,
		[]cipher.FileMatcher{cipher.MatchExt("yaml", "yml", "json")},
	)
	if err != nil {
		log.Fatal(err)
	}
}

// ExampleEncodeWalkWith demonstrates bounded-parallelism walking with
// observability callbacks for completed and skipped files.
func ExampleEncodeWalkWith() {
	const recipient = "age1..."
	enc := cipher.NewEncoder(cipherage.MustNewProvider(recipient))
	opts := cipher.WalkOptions{
		Parallelism: 4,
		OnFile:      func(p string, n int) { log.Printf("encrypted %s (%d)", p, n) },
		OnSkip:      func(p string, reason error) { log.Printf("skipped %s: %v", p, reason) },
	}
	err := cipher.EncodeWalkWith(
		context.Background(), afero.NewOsFs(), "./secrets", enc,
		[]cipher.FileMatcher{cipher.MatchExt("yaml", "json")}, opts,
	)
	if err != nil {
		log.Fatal(err)
	}
}

// ExampleRouter shows how to encrypt different files with different
// key providers based on path matching.
func ExampleRouter() {
	prodProvider := cipherage.MustNewProvider("age1prod...")
	devProvider := cipherage.MustNewProvider("age1dev...")
	router := cipher.NewRouter(
		cipher.Rule{
			Match:    cipher.FileMatcherFunc(func(p string) bool { return contains(p, "prod") }),
			Provider: prodProvider,
		},
		cipher.Rule{
			Match:    cipher.MatchAll(),
			Provider: devProvider,
		},
	)
	enc := cipher.NewRoutedEncoder(router, cipher.EncoderOptions{})
	out, err := enc.Encode(
		context.Background(), "secrets/prod/db.yaml", []byte("user: alice\n"),
	)
	if err != nil {
		log.Fatal(err)
	}
	_ = out
}

// ExampleEdit shows the decrypt-mutate-re-encrypt-write flow.
func ExampleEdit() {
	const recipient = "age1..."
	enc := cipher.NewEncoder(cipherage.MustNewProvider(recipient))
	dec := cipher.NewDecoder()
	files := afero.NewOsFs()
	err := cipher.Edit(
		context.Background(), files, "secrets.yaml", enc, dec,
		func(plaintext []byte) ([]byte, error) {
			return append(plaintext, []byte("new_key: value\n")...), nil
		},
	)
	if err != nil {
		log.Fatal(err)
	}
}

// ExampleRotate generates a new data key and re-encrypts the payload.
func ExampleRotate() {
	const recipient = "age1..."
	enc := cipher.NewEncoder(cipherage.MustNewProvider(recipient))
	dec := cipher.NewDecoder()
	rotated, err := cipher.Rotate(
		context.Background(), "secrets.yaml", []byte("..."), enc, dec,
	)
	if err != nil {
		log.Fatal(err)
	}
	_ = rotated
}

// ExampleAddRecipient shows how to grant another recipient access to
// an already-encrypted file without re-encrypting its payload.
func ExampleAddRecipient() {
	newRecipient := cipherage.MustNewProvider("age1bob...")
	updated, err := cipher.AddRecipient(
		context.Background(), "secrets.yaml", []byte("..."),
		newRecipient, cipher.DecoderOptions{},
	)
	if err != nil {
		log.Fatal(err)
	}
	_ = updated
}

// ExampleRemoveRecipient revokes a recipient by their identifier.
func ExampleRemoveRecipient() {
	pruned, err := cipher.RemoveRecipient("secrets.yaml", []byte("..."), "age1bob...")
	if err != nil {
		log.Fatal(err)
	}
	_ = pruned
}

// contains is a tiny path helper for the router example. The standard
// library equivalent is strings.Contains.
func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
