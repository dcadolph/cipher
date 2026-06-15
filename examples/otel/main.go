// Package main demonstrates cipher/otelcipher. An in-memory tracer
// captures spans emitted around every encode and decode call so the
// example can print them without any external collector.
package main

import (
	"context"
	"fmt"
	"log"
	"os"

	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	"github.com/dcadolph/cipher"
	"github.com/dcadolph/cipher/age"
	"github.com/dcadolph/cipher/otelcipher"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

// run wires the example end to end and returns any error so the
// TracerProvider Shutdown defer runs even on the failure path.
func run() error {
	ctx := context.Background()

	id, err := age.GenerateIdentity()
	if err != nil {
		return fmt.Errorf("generate age identity: %w", err)
	}
	if err := os.Setenv("SOPS_AGE_KEY", id.Secret); err != nil {
		return fmt.Errorf("set SOPS_AGE_KEY: %w", err)
	}

	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exporter))
	defer func() { _ = tp.Shutdown(ctx) }()
	tracer := tp.Tracer("cipher-example")

	provider, err := age.NewProvider(id.Recipient)
	if err != nil {
		return fmt.Errorf("age provider: %w", err)
	}
	tracedProvider := otelcipher.WrapKeyProvider(provider, tracer)
	tracedEnc := otelcipher.WrapEncoder(cipher.NewEncoder(tracedProvider), tracer)
	tracedDec := otelcipher.WrapDecoder(cipher.NewDecoder(), tracer)

	plain := []byte("trace: every step\n")
	ciphertext, err := tracedEnc.Encode(ctx, "secrets.yaml", plain)
	if err != nil {
		return fmt.Errorf("encode: %w", err)
	}
	if _, err := tracedDec.Decode(ctx, "secrets.yaml", ciphertext); err != nil {
		return fmt.Errorf("decode: %w", err)
	}

	fmt.Printf("captured %d spans:\n", len(exporter.GetSpans()))
	for _, span := range exporter.GetSpans() {
		fmt.Printf("  %-30s status=%s\n", span.Name, span.Status.Code)
	}
	return nil
}
