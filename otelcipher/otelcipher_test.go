package otelcipher_test

import (
	"context"
	"errors"
	"testing"

	"github.com/getsops/sops/v3"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	"github.com/dcadolph/cipher"
	"github.com/dcadolph/cipher/ciphertest"
	"github.com/dcadolph/cipher/otelcipher"
)

// newTracer returns a tracer backed by an in-memory span recorder so
// tests can assert on emitted spans.
func newTracer(t *testing.T) (*tracetest.SpanRecorder, *sdktrace.TracerProvider) {
	t.Helper()
	rec := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(rec))
	return rec, tp
}

// TestWrapEncoderEmitsSpan verifies a span is created with expected
// attributes on a successful Encode.
func TestWrapEncoderEmitsSpan(t *testing.T) {
	kp, _ := ciphertest.NewProvider(t)
	rec, tp := newTracer(t)
	enc := otelcipher.WrapEncoder(cipher.NewEncoder(kp), tp.Tracer("test"))
	out, err := enc.Encode(context.Background(), "x.yaml", []byte("foo: bar\n"))
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	spans := rec.Ended()
	if len(spans) != 1 {
		t.Fatalf("spans = %d, want 1", len(spans))
	}
	span := spans[0]
	if span.Name() != "cipher.Encode" {
		t.Errorf("name = %q", span.Name())
	}
	wantAttrs := map[string]any{
		"cipher.path":             "x.yaml",
		"cipher.plaintext_bytes":  int64(len("foo: bar\n")),
		"cipher.ciphertext_bytes": int64(len(out)),
	}
	for _, kv := range span.Attributes() {
		w, ok := wantAttrs[string(kv.Key)]
		if !ok {
			continue
		}
		if got := kvValue(kv); got != w {
			t.Errorf("attr %s = %v, want %v", kv.Key, got, w)
		}
		delete(wantAttrs, string(kv.Key))
	}
	if len(wantAttrs) != 0 {
		t.Errorf("missing attributes: %v", wantAttrs)
	}
}

// TestWrapEncoderRecordsErrors verifies that an Encode error sets the
// span status to error.
func TestWrapEncoderRecordsErrors(t *testing.T) {
	rec, tp := newTracer(t)
	boom := errors.New("boom")
	enc := otelcipher.WrapEncoder(
		cipher.EncoderFunc(func(context.Context, string, []byte) ([]byte, error) {
			return nil, boom
		}),
		tp.Tracer("test"),
	)
	_, err := enc.Encode(context.Background(), "x.yaml", []byte("x"))
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want errors.Is boom", err)
	}
	spans := rec.Ended()
	if len(spans) != 1 {
		t.Fatalf("spans = %d, want 1", len(spans))
	}
	if spans[0].Status().Code != codes.Error {
		t.Errorf("status code = %v, want Error", spans[0].Status().Code)
	}
}

// TestWrapDecoderEmitsSpan verifies the decoder span emits attributes.
func TestWrapDecoderEmitsSpan(t *testing.T) {
	kp, _ := ciphertest.NewProvider(t)
	rec, tp := newTracer(t)
	enc := cipher.NewEncoder(kp)
	ct, _ := enc.Encode(context.Background(), "x.yaml", []byte("foo: bar\n"))

	dec := otelcipher.WrapDecoder(cipher.NewDecoder(), tp.Tracer("test"))
	_, err := dec.Decode(context.Background(), "x.yaml", ct)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	spans := rec.Ended()
	if len(spans) != 1 || spans[0].Name() != "cipher.Decode" {
		t.Fatalf("spans = %+v", spans)
	}
}

// TestWrapKeyProviderEmitsSpan verifies the KeyGroups span.
func TestWrapKeyProviderEmitsSpan(t *testing.T) {
	kp, _ := ciphertest.NewProvider(t)
	rec, tp := newTracer(t)
	wrapped := otelcipher.WrapKeyProvider(kp, tp.Tracer("test"))
	if _, err := wrapped.KeyGroups(context.Background()); err != nil {
		t.Fatalf("KeyGroups: %v", err)
	}
	spans := rec.Ended()
	if len(spans) != 1 || spans[0].Name() != "cipher.KeyGroups" {
		t.Fatalf("spans = %+v", spans)
	}
}

// TestWrapDecoderRecordsErrors verifies the decode error path sets
// Error status on the span and records the error.
func TestWrapDecoderRecordsErrors(t *testing.T) {
	rec, tp := newTracer(t)
	dec := otelcipher.WrapDecoder(cipher.NewDecoder(), tp.Tracer("test"))
	_, err := dec.Decode(context.Background(), "x.yaml", []byte("not a sops file"))
	if err == nil {
		t.Fatal("Decode err = nil, want error")
	}
	spans := rec.Ended()
	if len(spans) != 1 || spans[0].Name() != "cipher.Decode" {
		t.Fatalf("spans = %+v", spans)
	}
	if spans[0].Status().Code != codes.Error {
		t.Errorf("status code = %v, want Error", spans[0].Status().Code)
	}
}

// TestWrapKeyProviderRecordsErrors verifies the KeyGroups error path
// sets Error status on the span and records the underlying error.
func TestWrapKeyProviderRecordsErrors(t *testing.T) {
	rec, tp := newTracer(t)
	errKP := cipher.KeyProviderFunc(func(context.Context) ([]sops.KeyGroup, error) {
		return nil, errFakeKP
	})
	wrapped := otelcipher.WrapKeyProvider(errKP, tp.Tracer("test"))
	_, err := wrapped.KeyGroups(context.Background())
	if !errors.Is(err, errFakeKP) {
		t.Fatalf("KeyGroups err = %v, want errFakeKP", err)
	}
	spans := rec.Ended()
	if len(spans) != 1 || spans[0].Name() != "cipher.KeyGroups" {
		t.Fatalf("spans = %+v", spans)
	}
	if spans[0].Status().Code != codes.Error {
		t.Errorf("status code = %v, want Error", spans[0].Status().Code)
	}
}

// TestWrapNilPanics confirms each wrapper panics when its required
// argument is nil. Mirrors the documented contract.
func TestWrapNilPanics(t *testing.T) {
	t.Parallel()
	tests := []struct {
		Name string
		Run  func()
	}{
		{"encoder", func() { otelcipher.WrapEncoder(nil, nil) }},
		{"decoder", func() { otelcipher.WrapDecoder(nil, nil) }},
		{"keyprovider", func() { otelcipher.WrapKeyProvider(nil, nil) }},
	}
	for i, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Errorf("Test %d (%s): expected panic", i, test.Name)
				}
			}()
			test.Run()
		})
	}
}

// errFakeKP is a sentinel error returned by the failing KeyProvider
// in the error path test.
var errFakeKP = errors.New("otelcipher_test: synthetic key provider error")

// kvValue extracts a comparable Go value from an OTel attribute.
func kvValue(kv attribute.KeyValue) any {
	switch kv.Value.Type() {
	case attribute.STRING:
		return kv.Value.AsString()
	case attribute.INT64:
		return kv.Value.AsInt64()
	case attribute.BOOL:
		return kv.Value.AsBool()
	case attribute.FLOAT64:
		return kv.Value.AsFloat64()
	default:
		return kv.Value.String()
	}
}
