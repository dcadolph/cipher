// Package otelcipher emits OpenTelemetry spans for cipher operations.
// It is an opt-in subpackage so the OTel dependency is only pulled in
// when explicitly imported.
package otelcipher

import (
	"context"

	"github.com/getsops/sops/v3"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/dcadolph/cipher"
)

// TracerName is the default OTel tracer name used by Wrap helpers when
// the caller supplies a nil tracer.
const TracerName = "github.com/dcadolph/cipher"

// WrapEncoder returns a cipher.Encoder that emits an OTel span around
// every Encode call. The span is named "cipher.Encode" and carries
// path, plaintext byte count, and ciphertext byte count attributes.
// Errors are recorded on the span and set its status to error.
func WrapEncoder(enc cipher.Encoder, tracer trace.Tracer) cipher.Encoder {
	if enc == nil {
		panic("otelcipher: WrapEncoder: encoder required")
	}
	if tracer == nil {
		tracer = otel.Tracer(TracerName)
	}
	return cipher.EncoderFunc(func(ctx context.Context, path string, data []byte) ([]byte, error) {
		ctx, span := tracer.Start(ctx, "cipher.Encode",
			trace.WithAttributes(
				attribute.String("cipher.path", path),
				attribute.Int("cipher.plaintext_bytes", len(data)),
			),
		)
		defer span.End()
		out, err := enc.Encode(ctx, path, data)
		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
			return nil, err
		}
		span.SetAttributes(attribute.Int("cipher.ciphertext_bytes", len(out)))
		return out, nil
	})
}

// WrapDecoder returns a cipher.Decoder that emits an OTel span around
// every Decode call.
func WrapDecoder(dec cipher.Decoder, tracer trace.Tracer) cipher.Decoder {
	if dec == nil {
		panic("otelcipher: WrapDecoder: decoder required")
	}
	if tracer == nil {
		tracer = otel.Tracer(TracerName)
	}
	return cipher.DecoderFunc(func(ctx context.Context, path string, data []byte) ([]byte, error) {
		ctx, span := tracer.Start(ctx, "cipher.Decode",
			trace.WithAttributes(
				attribute.String("cipher.path", path),
				attribute.Int("cipher.ciphertext_bytes", len(data)),
			),
		)
		defer span.End()
		out, err := dec.Decode(ctx, path, data)
		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
			return nil, err
		}
		span.SetAttributes(attribute.Int("cipher.plaintext_bytes", len(out)))
		return out, nil
	})
}

// WrapKeyProvider returns a cipher.KeyProvider that emits an OTel span
// around every KeyGroups call. Useful when key sourcing is slow
// (e.g. KMS lookups) and you want timing visibility.
func WrapKeyProvider(kp cipher.KeyProvider, tracer trace.Tracer) cipher.KeyProvider {
	if kp == nil {
		panic("otelcipher: WrapKeyProvider: provider required")
	}
	if tracer == nil {
		tracer = otel.Tracer(TracerName)
	}
	return cipher.KeyProviderFunc(func(ctx context.Context) ([]sops.KeyGroup, error) {
		ctx, span := tracer.Start(ctx, "cipher.KeyGroups")
		defer span.End()
		groups, err := kp.KeyGroups(ctx)
		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
			return nil, err
		}
		var keys int
		for _, g := range groups {
			keys += len(g)
		}
		span.SetAttributes(
			attribute.Int("cipher.groups", len(groups)),
			attribute.Int("cipher.keys", keys),
		)
		return groups, nil
	})
}
