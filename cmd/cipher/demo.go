package main

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

// webFS holds the embedded cinematic assets served by `cipher demo`.
// Files live under cmd/cipher/web and are added to the binary at build
// time via go:embed.
//
//go:embed web
var webFS embed.FS

// demoExplainers is the canonical list of cinematic slugs the demo
// command knows about. Adding a new cinematic means dropping
// explainer-<slug>.html and explainer-<slug>.js into web/ and adding
// the slug here.
var demoExplainers = []string{"intro", "how-it-works", "tour", "walk", "recipients", "precommit"}

// newDemoCmd returns the `cipher demo` subcommand. It spins up an
// embedded HTTP server on a free local port, opens the user's browser
// to a tile grid of cinematic explainers, and runs them in-browser.
// Everything ships inside the cipher binary as embedded static assets.
func newDemoCmd() *cobra.Command {
	var (
		addr      string
		noBrowser bool
		explainer string
	)
	cmd := &cobra.Command{
		Use:   "demo",
		Short: "Open in-browser cinematic demos of cipher",
		Long: "Demo launches an embedded HTTP server, opens your default\n" +
			"browser to a tile of cinematic explainers, and serves them\n" +
			"end to end. The server runs until you press Ctrl+C.\n\n" +
			"Available explainers: intro, how-it-works, tour, walk, recipients, precommit.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if explainer != "" && !isKnownExplainer(explainer) {
				return fmt.Errorf("unknown explainer %q (valid: %s)",
					explainer, strings.Join(demoExplainers, ", "))
			}
			return runDemo(cmd.Context(), addr, !noBrowser, explainer)
		},
	}
	cmd.Flags().StringVar(&addr, "addr", "127.0.0.1:0",
		"listen address; default chooses an ephemeral port")
	cmd.Flags().BoolVar(&noBrowser, "no-browser", false,
		"print the URL instead of opening the browser")
	cmd.Flags().StringVar(&explainer, "explainer", "",
		"jump to a specific explainer slug"+
			" (intro, how-it-works, tour, walk, recipients, precommit)")
	return cmd
}

// runDemo starts the embedded HTTP server bound to addr, optionally
// opens the user's browser, and blocks until the context is canceled.
// startPath is the URL path to open in the browser ("/" for the
// library landing, or "/explainer/<slug>" for a direct route).
func runDemo(ctx context.Context, addr string, openBrowser bool, explainer string) error {
	mux, err := newDemoMux()
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("demo: listen %q: %w", addr, err)
	}
	srv := &http.Server{
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	startPath := "/"
	if explainer != "" {
		startPath = "/explainer/" + explainer
	}
	base := "http://" + ln.Addr().String()
	url := base + startPath

	fmt.Fprintln(os.Stderr, "cipher demo serving at", base)
	fmt.Fprintln(os.Stderr, "opening", url)

	errCh := make(chan error, 1)
	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
			return
		}
		errCh <- nil
	}()

	if openBrowser {
		if err := openInBrowser(url); err != nil {
			fmt.Fprintln(os.Stderr, "could not open browser:", err)
			fmt.Fprintln(os.Stderr, "open this URL manually:", url)
		}
	}

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
		return nil
	case err := <-errCh:
		return err
	}
}

// newDemoMux returns the HTTP mux that serves the cinematic assets.
// Routes:
//
//   - GET /                            -> index.html (library landing)
//   - GET /explainer/<slug>            -> explainer-<slug>.html
//   - GET /trailer                     -> redirect to /explainer/tour
//   - GET /<asset>                     -> embedded static file
func newDemoMux() (*http.ServeMux, error) {
	sub, err := fs.Sub(webFS, "web")
	if err != nil {
		return nil, fmt.Errorf("demo: sub fs: %w", err)
	}
	for _, slug := range demoExplainers {
		if _, err := fs.Stat(sub, "explainer-"+slug+".html"); err != nil {
			return nil, fmt.Errorf("demo: missing explainer-%s.html: %w", slug, err)
		}
		if _, err := fs.Stat(sub, "explainer-"+slug+".js"); err != nil {
			return nil, fmt.Errorf("demo: missing explainer-%s.js: %w", slug, err)
		}
	}

	mux := http.NewServeMux()
	fileServer := http.FileServer(http.FS(sub))

	serveEmbedded := func(w http.ResponseWriter, name string) {
		data, err := fs.ReadFile(sub, name)
		if err != nil {
			http.Error(w, "asset missing: "+name, http.StatusInternalServerError)
			return
		}
		ct := "application/octet-stream"
		switch {
		case strings.HasSuffix(name, ".html"):
			ct = "text/html; charset=utf-8"
		case strings.HasSuffix(name, ".css"):
			ct = "text/css; charset=utf-8"
		case strings.HasSuffix(name, ".js"):
			ct = "application/javascript; charset=utf-8"
		}
		w.Header().Set("Content-Type", ct)
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(data)))
		_, _ = w.Write(data)
	}

	mux.HandleFunc("GET /trailer", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/explainer/tour", http.StatusMovedPermanently)
	})
	mux.HandleFunc("GET /explainer/{slug}", func(w http.ResponseWriter, r *http.Request) {
		slug := r.PathValue("slug")
		if !isKnownExplainer(slug) {
			http.NotFound(w, r)
			return
		}
		serveEmbedded(w, "explainer-"+slug+".html")
	})
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, _ *http.Request) {
		serveEmbedded(w, "index.html")
	})
	mux.Handle("GET /", fileServer)
	return mux, nil
}

// isKnownExplainer reports whether slug is in demoExplainers.
func isKnownExplainer(slug string) bool {
	return slices.Contains(demoExplainers, slug)
}

// openInBrowser launches the user's default browser pointed at url.
// Returns the error from the underlying OS call. Best-effort: a
// missing browser is reported to the caller, never panics.
func openInBrowser(url string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	return cmd.Start()
}
