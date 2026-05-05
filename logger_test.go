package cipher_test

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"

	"github.com/dcadolph/cipher"
	cipherage "github.com/dcadolph/cipher/age"
)

// captureLogger collects log records for assertion.
type captureLogger struct {
	mu      sync.Mutex
	records []string
}

func (c *captureLogger) Debugf(f string, a ...any) { c.add("DEBUG: "+f, a...) }
func (c *captureLogger) Infof(f string, a ...any)  { c.add("INFO: "+f, a...) }
func (c *captureLogger) Warnf(f string, a ...any)  { c.add("WARN: "+f, a...) }

func (c *captureLogger) add(f string, a ...any) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.records = append(c.records, fmt.Sprintf(f, a...))
}

func (c *captureLogger) lines() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]string, len(c.records))
	copy(out, c.records)
	return out
}

// TestEncoderLoggerAndCallback verifies that the encoder logger and
// OnEncrypt callback are invoked with expected values.
func TestEncoderLoggerAndCallback(t *testing.T) {
	recipient := newAgeIdentity(t)
	log := &captureLogger{}
	var hitPath string
	var hitPlain, hitCipher int
	enc := cipher.NewEncoderWith(
		cipherage.MustNewProvider(recipient),
		cipher.EncoderOptions{
			Logger: log,
			OnEncrypt: func(path string, plain, cipherBytes int) {
				hitPath, hitPlain, hitCipher = path, plain, cipherBytes
			},
		},
	)
	plain := []byte("foo: bar\n")
	out, err := enc.Encode(context.Background(), "x.yaml", plain)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if hitPath != "x.yaml" || hitPlain != len(plain) || hitCipher != len(out) {
		t.Errorf("OnEncrypt called with (%q, %d, %d), want (%q, %d, %d)",
			hitPath, hitPlain, hitCipher, "x.yaml", len(plain), len(out))
	}
	saw := strings.Join(log.lines(), "\n")
	if !strings.Contains(saw, "cipher.Encode start") || !strings.Contains(saw, "cipher.Encode done") {
		t.Errorf("logger did not record start+done events, got:\n%s", saw)
	}
}

// TestDecoderLoggerAndCallback verifies the decoder side.
func TestDecoderLoggerAndCallback(t *testing.T) {
	recipient := newAgeIdentity(t)
	enc := cipher.NewEncoder(cipherage.MustNewProvider(recipient))
	plain := []byte("foo: bar\n")
	ct, err := enc.Encode(context.Background(), "x.yaml", plain)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}

	log := &captureLogger{}
	var hitPath string
	var hitCipher, hitPlain int
	dec := cipher.NewDecoderWith(cipher.DecoderOptions{
		Logger: log,
		OnDecrypt: func(path string, cipherBytes, plainBytes int) {
			hitPath, hitCipher, hitPlain = path, cipherBytes, plainBytes
		},
	})
	out, err := dec.Decode(context.Background(), "x.yaml", ct)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if hitPath != "x.yaml" || hitCipher != len(ct) || hitPlain != len(out) {
		t.Errorf("OnDecrypt called with (%q, %d, %d), want (%q, %d, %d)",
			hitPath, hitCipher, hitPlain, "x.yaml", len(ct), len(out))
	}
	saw := strings.Join(log.lines(), "\n")
	if !strings.Contains(saw, "cipher.Decode start") {
		t.Errorf("logger missing Decode events, got:\n%s", saw)
	}
}

// TestNopLogger verifies the public NopLogger does nothing and is
// substitutable when no logger is supplied.
func TestNopLogger(t *testing.T) {
	t.Parallel()
	cipher.NopLogger.Debugf("debug %d", 1)
	cipher.NopLogger.Infof("info %d", 2)
	cipher.NopLogger.Warnf("warn %d", 3)
}

// TestSlogLogger verifies SlogLogger forwards every level into the
// wrapped *slog.Logger.
func TestSlogLogger(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	handler := slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})
	logger := cipher.SlogLogger(slog.New(handler))

	logger.Debugf("debug message %d", 1)
	logger.Infof("info message %d", 2)
	logger.Warnf("warn message %d", 3)

	out := buf.String()
	for _, want := range []string{"debug message 1", "info message 2", "warn message 3"} {
		if !strings.Contains(out, want) {
			t.Errorf("slog output missing %q, got:\n%s", want, out)
		}
	}
}

// TestSlogLoggerNilPanics verifies SlogLogger panics on nil input so
// misconfiguration is caught at construction time.
func TestSlogLoggerNilPanics(t *testing.T) {
	t.Parallel()
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic on nil logger")
		}
	}()
	_ = cipher.SlogLogger(nil)
}
