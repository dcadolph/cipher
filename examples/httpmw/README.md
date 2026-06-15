# httpmw example

Self-contained. Starts an in-process [httptest](https://pkg.go.dev/net/http/httptest) server with `EncryptResponseBody` middleware. Makes a request, prints the encrypted body, decrypts locally, prints the plaintext.

```sh
go run ./examples/httpmw
```

The `httpmw` package also exposes `DecryptRequestBody` for the inbound direction.
