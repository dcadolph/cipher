// Package httpmw provides net/http middleware that decrypts inbound
// request bodies or encrypts outbound response bodies using a
// cipher.Decoder or cipher.Encoder.
//
// The middleware treats each request body as a single sops-encrypted
// payload. Use this for service-to-service exchange of secret blobs
// where both ends agree on the sops format and decrypt path.
package httpmw

import (
	"bytes"
	"fmt"
	"io"
	"net/http"

	"github.com/dcadolph/cipher"
)

// DefaultMaxBodyBytes is the default per-request body cap used when no
// WithMaxBodyBytes option is supplied.
const DefaultMaxBodyBytes int64 = 10 << 20

// PathFunc maps an HTTP request to the path string passed to the
// wrapped Encoder or Decoder. Sops uses this for format detection.
type PathFunc func(*http.Request) string

// DefaultPathFunc returns r.URL.Path.
func DefaultPathFunc(r *http.Request) string { return r.URL.Path }

// Option tunes a middleware.
type Option func(*config)

// WithMaxBodyBytes caps inbound bodies to n bytes. Requests exceeding
// the cap receive 413 (Request Entity Too Large).
func WithMaxBodyBytes(n int64) Option { return func(c *config) { c.maxBody = n } }

// WithLogger sets the logger used to report errors. Nil uses cipher.NopLogger.
func WithLogger(log cipher.Logger) Option { return func(c *config) { c.log = log } }

// config is the resolved option set for a middleware.
type config struct {
	maxBody int64
	log     cipher.Logger
}

// applyOptions returns a config with defaults applied.
func applyOptions(opts []Option) *config {
	c := &config{maxBody: DefaultMaxBodyBytes, log: cipher.NopLogger}
	for _, opt := range opts {
		opt(c)
	}
	if c.log == nil {
		c.log = cipher.NopLogger
	}
	return c
}

// DecryptRequestBody returns middleware that reads the entire request
// body, decrypts it via dec, and replaces r.Body with the plaintext
// before invoking the next handler. The Content-Length header is
// rewritten to match the plaintext.
//
// Decryption failures respond with 400. Bodies exceeding the cap
// respond with 413. The next handler is not invoked in either case.
func DecryptRequestBody(
	dec cipher.Decoder, pathFn PathFunc, opts ...Option,
) func(http.Handler) http.Handler {
	if dec == nil {
		panic("cipher/httpmw: DecryptRequestBody: decoder required")
	}
	if pathFn == nil {
		pathFn = DefaultPathFunc
	}
	cfg := applyOptions(opts)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			path := pathFn(r)
			body, err := readBody(r.Body, cfg.maxBody)
			if err != nil {
				cfg.log.Warnf("httpmw.DecryptRequestBody read: %v", err)
				http.Error(w, err.Error(), errStatus(err))
				return
			}
			plain, err := dec.Decode(r.Context(), path, body)
			if err != nil {
				cfg.log.Warnf("httpmw.DecryptRequestBody decode: path=%s err=%v", path, err)
				http.Error(w, "decrypt: "+err.Error(), http.StatusBadRequest)
				return
			}
			r.Body = io.NopCloser(bytes.NewReader(plain))
			r.ContentLength = int64(len(plain))
			r.Header.Set("Content-Length", fmt.Sprintf("%d", len(plain)))
			next.ServeHTTP(w, r)
		})
	}
}

// EncryptResponseBody returns middleware that buffers the wrapped
// handler's response body and writes the encrypted form to the client.
// Encryption failures respond with 500 (after the inner handler has
// already produced a body that the client never sees).
func EncryptResponseBody(
	enc cipher.Encoder, pathFn PathFunc, opts ...Option,
) func(http.Handler) http.Handler {
	if enc == nil {
		panic("cipher/httpmw: EncryptResponseBody: encoder required")
	}
	if pathFn == nil {
		pathFn = DefaultPathFunc
	}
	cfg := applyOptions(opts)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			buf := &bufferedWriter{header: http.Header{}}
			next.ServeHTTP(buf, r)
			if buf.body.Len() == 0 {
				copyHeader(w.Header(), buf.header)
				w.WriteHeader(buf.statusOr(http.StatusOK))
				return
			}
			path := pathFn(r)
			out, err := enc.Encode(r.Context(), path, buf.body.Bytes())
			if err != nil {
				cfg.log.Warnf("httpmw.EncryptResponseBody encode: path=%s err=%v", path, err)
				http.Error(w, "encrypt failed", http.StatusInternalServerError)
				return
			}
			copyHeader(w.Header(), buf.header)
			w.Header().Set("Content-Length", fmt.Sprintf("%d", len(out)))
			w.WriteHeader(buf.statusOr(http.StatusOK))
			_, _ = w.Write(out)
		})
	}
}

// readBody reads from body up to maxBytes+1 to detect oversize inputs.
// Returns an errTooLarge if the cap is exceeded.
func readBody(body io.ReadCloser, maxBytes int64) ([]byte, error) {
	defer func() { _ = body.Close() }()
	limited := io.LimitReader(body, maxBytes+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxBytes {
		return nil, errTooLarge{limit: maxBytes}
	}
	return data, nil
}

// errTooLarge is returned by readBody when the body exceeds the configured cap.
type errTooLarge struct{ limit int64 }

// Error implements error.
func (e errTooLarge) Error() string {
	return fmt.Sprintf("request body exceeds %d bytes", e.limit)
}

// errStatus maps a read error to an HTTP status code.
func errStatus(err error) int {
	if _, ok := err.(errTooLarge); ok {
		return http.StatusRequestEntityTooLarge
	}
	return http.StatusBadRequest
}

// bufferedWriter is a http.ResponseWriter that buffers writes so the
// middleware can mutate the body before flushing to the client.
type bufferedWriter struct {
	header http.Header
	body   bytes.Buffer
	status int
}

// Header implements http.ResponseWriter.
func (b *bufferedWriter) Header() http.Header { return b.header }

// Write implements http.ResponseWriter.
func (b *bufferedWriter) Write(p []byte) (int, error) { return b.body.Write(p) }

// WriteHeader implements http.ResponseWriter.
func (b *bufferedWriter) WriteHeader(s int) { b.status = s }

// statusOr returns the recorded status code or fallback if none was set.
func (b *bufferedWriter) statusOr(fallback int) int {
	if b.status == 0 {
		return fallback
	}
	return b.status
}

// copyHeader copies entries from src into dst.
func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}
