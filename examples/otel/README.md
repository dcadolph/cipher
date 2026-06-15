# otel example

Self-contained. Wraps the encoder, decoder, and key provider with [OpenTelemetry](https://opentelemetry.io/) spans. Uses an in-memory exporter so no collector is required.

```sh
go run ./examples/otel
```

In production, swap the in-memory exporter for an OTLP exporter pointing at your collector.
