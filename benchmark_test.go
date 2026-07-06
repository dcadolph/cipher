package cipher_test

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"

	"filippo.io/age"
	"github.com/spf13/afero"

	"github.com/dcadolph/cipher"
	cipherage "github.com/dcadolph/cipher/age"
)

// benchSizes drives the size-parametrized benchmarks below. The sizes
// are chosen to bracket realistic secret files (a single API token, a
// small config, a large CI fixture).
var benchSizes = []int{
	1 << 10,  // 1 KiB
	8 << 10,  // 8 KiB
	64 << 10, // 64 KiB
	1 << 20,  // 1 MiB
}

// benchAgeRecipient returns an age recipient suitable for the benches
// in this file. It also configures SOPS_AGE_KEY so decoders can decrypt.
// b.Setenv is used so each benchmark cleans up.
func benchAgeRecipient(b *testing.B) string {
	b.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		b.Fatalf("identity: %v", err)
	}
	b.Setenv("SOPS_AGE_KEY", id.String())
	return id.Recipient().String()
}

// fakeYAMLOfSize returns deterministic YAML of approximately n bytes,
// kept structurally valid so sops can parse it.
func fakeYAMLOfSize(n int) []byte {
	const keyLine = "key%05d: value%05d\n"
	buf := make([]byte, 0, n+128)
	for i := 0; len(buf) < n; i++ {
		buf = fmt.Appendf(buf, keyLine, i, i)
	}
	return buf[:n]
}

// BenchmarkEncodeYAML measures full sops Encode at each size.
func BenchmarkEncodeYAML(b *testing.B) {
	recipient := benchAgeRecipient(b)
	enc := cipher.NewEncoder(cipherage.MustNewProvider(recipient))
	ctx := context.Background()

	for _, size := range benchSizes {
		data := fakeYAMLOfSize(size)
		b.Run(fmt.Sprintf("size=%d", size), func(b *testing.B) {
			b.SetBytes(int64(size))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := enc.Encode(ctx, "secrets.yaml", data); err != nil {
					b.Fatalf("Encode: %v", err)
				}
			}
		})
	}
}

// BenchmarkDecodeYAML measures full sops Decode at each size.
func BenchmarkDecodeYAML(b *testing.B) {
	recipient := benchAgeRecipient(b)
	enc := cipher.NewEncoder(cipherage.MustNewProvider(recipient))
	dec := cipher.NewDecoder()
	ctx := context.Background()

	for _, size := range benchSizes {
		plain := fakeYAMLOfSize(size)
		encrypted, err := enc.Encode(ctx, "secrets.yaml", plain)
		if err != nil {
			b.Fatalf("seed Encode: %v", err)
		}
		b.Run(fmt.Sprintf("size=%d", size), func(b *testing.B) {
			b.SetBytes(int64(size))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := dec.Decode(ctx, "secrets.yaml", encrypted); err != nil {
					b.Fatalf("Decode: %v", err)
				}
			}
		})
	}
}

// BenchmarkEncodePerFormat compares format-specific overhead at a fixed
// 8 KiB plaintext size.
func BenchmarkEncodePerFormat(b *testing.B) {
	recipient := benchAgeRecipient(b)
	enc := cipher.NewEncoder(cipherage.MustNewProvider(recipient))
	ctx := context.Background()

	cases := []struct {
		Name string
		Path string
		Data []byte
	}{
		{"yaml", "secrets.yaml", fakeYAMLOfSize(8 << 10)},
		{"json", "secrets.json", fakeJSONOfSize(8 << 10)},
		{"dotenv", "secrets.env", fakeDotenvOfSize(8 << 10)},
		{"binary", "secrets.bin", fakeBinaryOfSize(8 << 10)},
	}
	for _, c := range cases {
		b.Run(c.Name, func(b *testing.B) {
			b.SetBytes(int64(len(c.Data)))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := enc.Encode(ctx, c.Path, c.Data); err != nil {
					b.Fatalf("Encode %s: %v", c.Name, err)
				}
			}
		})
	}
}

// BenchmarkInspect measures the cost of reading metadata without
// decryption. Important because it is the hot path of recipient diff,
// precommit, and audit tooling.
func BenchmarkInspect(b *testing.B) {
	recipient := benchAgeRecipient(b)
	enc := cipher.NewEncoder(cipherage.MustNewProvider(recipient))
	ctx := context.Background()
	encrypted, err := enc.Encode(ctx, "secrets.yaml", fakeYAMLOfSize(8<<10))
	if err != nil {
		b.Fatalf("seed Encode: %v", err)
	}

	b.SetBytes(int64(len(encrypted)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := cipher.InspectPath("secrets.yaml", encrypted); err != nil {
			b.Fatalf("InspectPath: %v", err)
		}
	}
}

// BenchmarkIsEncryptedPath measures the cheap-path "is this encrypted?"
// check. Heavily used in walkers' skip detection.
func BenchmarkIsEncryptedPath(b *testing.B) {
	recipient := benchAgeRecipient(b)
	enc := cipher.NewEncoder(cipherage.MustNewProvider(recipient))
	ctx := context.Background()
	encrypted, err := enc.Encode(ctx, "secrets.yaml", fakeYAMLOfSize(8<<10))
	if err != nil {
		b.Fatalf("seed Encode: %v", err)
	}
	plain := fakeYAMLOfSize(8 << 10)

	b.Run("encrypted", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if !cipher.IsEncryptedPath("secrets.yaml", encrypted) {
				b.Fatal("IsEncryptedPath returned false")
			}
		}
	})
	b.Run("plain", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if cipher.IsEncryptedPath("secrets.yaml", plain) {
				b.Fatal("IsEncryptedPath returned true")
			}
		}
	})
}

// BenchmarkEncodeWalkParallelism compares serial and parallel walker
// throughput on a fixed file count.
func BenchmarkEncodeWalkParallelism(b *testing.B) {
	recipient := benchAgeRecipient(b)
	enc := cipher.NewEncoder(cipherage.MustNewProvider(recipient))
	ctx := context.Background()
	const fileCount = 16
	data := fakeYAMLOfSize(4 << 10)

	prepFS := func() afero.Fs {
		fs := afero.NewMemMapFs()
		for i := range fileCount {
			path := filepath.Join("/root", fmt.Sprintf("f%03d.yaml", i))
			if err := afero.WriteFile(fs, path, data, 0o600); err != nil {
				b.Fatalf("seed: %v", err)
			}
		}
		return fs
	}

	cases := []struct {
		Name        string
		Parallelism int
	}{
		{"serial", 1},
		{"parallel_4", 4},
		{"parallel_8", 8},
	}
	for _, c := range cases {
		b.Run(c.Name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				b.StopTimer()
				fs := prepFS()
				b.StartTimer()
				err := cipher.EncodeWalkWith(ctx, fs, "/root", enc, nil,
					cipher.WalkOptions{Parallelism: c.Parallelism})
				if err != nil {
					b.Fatalf("EncodeWalkWith: %v", err)
				}
			}
		})
	}
}

// BenchmarkDiffRecipients measures the hot path of secret-rotation
// audit tooling: two inspects plus a set diff.
func BenchmarkDiffRecipients(b *testing.B) {
	recipient := benchAgeRecipient(b)
	id2, err := age.GenerateX25519Identity()
	if err != nil {
		b.Fatalf("id2: %v", err)
	}

	enc1 := cipher.NewEncoder(cipherage.MustNewProvider(recipient))
	enc2 := cipher.NewEncoder(cipherage.MustNewProvider(id2.Recipient().String()))
	ctx := context.Background()
	plain := fakeYAMLOfSize(4 << 10)
	before, err := enc1.Encode(ctx, "secrets.yaml", plain)
	if err != nil {
		b.Fatalf("Encode before: %v", err)
	}
	after, err := enc2.Encode(ctx, "secrets.yaml", plain)
	if err != nil {
		b.Fatalf("Encode after: %v", err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := cipher.DiffRecipientsPath("secrets.yaml", before, after); err != nil {
			b.Fatalf("DiffRecipientsPath: %v", err)
		}
	}
}

// BenchmarkRotate measures end-to-end Rotate, which decrypts and
// re-encrypts in one call.
func BenchmarkRotate(b *testing.B) {
	recipient := benchAgeRecipient(b)
	enc := cipher.NewEncoder(cipherage.MustNewProvider(recipient))
	dec := cipher.NewDecoder()
	ctx := context.Background()
	encrypted, err := enc.Encode(ctx, "secrets.yaml", fakeYAMLOfSize(4<<10))
	if err != nil {
		b.Fatalf("seed Encode: %v", err)
	}

	b.SetBytes(int64(len(encrypted)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := cipher.Rotate(ctx, "secrets.yaml", encrypted, enc, dec); err != nil {
			b.Fatalf("Rotate: %v", err)
		}
	}
}

// BenchmarkMatcherMatch measures the matcher hot path. Walkers call
// Match once per file.
func BenchmarkMatcherMatch(b *testing.B) {
	cases := []struct {
		Name    string
		Matcher cipher.FileMatcher
		Path    string
	}{
		{
			Name:    "ext_yaml_hit",
			Matcher: cipher.MatchExt("yaml", "yml"),
			Path:    "secrets.yaml",
		},
		{
			Name:    "ext_yaml_miss",
			Matcher: cipher.MatchExt("yaml", "yml"),
			Path:    "notes.txt",
		},
		{
			Name:    "any_of",
			Matcher: cipher.MatchAnyOf(cipher.MatchExt("yaml"), cipher.MatchExt("json")),
			Path:    "secrets.json",
		},
		{
			Name:    "all_of",
			Matcher: cipher.MatchAllOf(cipher.MatchExt("yaml"), cipher.MatchAll()),
			Path:    "secrets.yaml",
		},
	}
	for _, c := range cases {
		b.Run(c.Name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_ = c.Matcher.Match(c.Path)
			}
		})
	}
}

// fakeJSONOfSize returns a structurally valid JSON object of about n bytes.
func fakeJSONOfSize(n int) []byte {
	buf := make([]byte, 0, n+128)
	buf = append(buf, '{')
	for i := 0; len(buf) < n-2; i++ {
		if i > 0 {
			buf = append(buf, ',')
		}
		buf = fmt.Appendf(buf, `"k%05d":"v%05d"`, i, i)
	}
	buf = append(buf, '}')
	return buf
}

// fakeDotenvOfSize returns a dotenv blob of about n bytes.
func fakeDotenvOfSize(n int) []byte {
	buf := make([]byte, 0, n+128)
	for i := 0; len(buf) < n; i++ {
		buf = fmt.Appendf(buf, "KEY_%05d=value_%05d\n", i, i)
	}
	return buf[:n]
}

// fakeBinaryOfSize returns deterministic bytes of length n.
func fakeBinaryOfSize(n int) []byte {
	buf := make([]byte, n)
	for i := range buf {
		buf[i] = byte(i % 251)
	}
	return buf
}
