package cipher

import (
	"context"
	"fmt"
	"log/slog"
)

// Logger is the minimal logging contract cipher uses for observability.
// It is satisfied by zap.SugaredLogger, logrus.Logger, and any other
// logger exposing Printf-style methods at three severity levels.
//
// Logger calls are made at the boundaries of encode/decode operations.
// They are best-effort and do not affect functional behavior.
//
// For structured logging that preserves attribute pairs (slog,
// zap.Logger), use SlogLogger to wrap a *slog.Logger.
type Logger interface {
	// Debugf logs a routine event (per-file encode/decode start, etc).
	Debugf(format string, args ...any)
	// Infof logs a notable event (e.g. completion of a walk).
	Infof(format string, args ...any)
	// Warnf logs a recoverable problem (skip on already-encrypted, etc).
	Warnf(format string, args ...any)
}

// NopLogger discards all log records. It is the default when no logger
// is supplied via options.
var NopLogger Logger = nopLogger{}

// nopLogger is the no-op Logger implementation.
type nopLogger struct{}

// Debugf does nothing.
func (nopLogger) Debugf(string, ...any) {}

// Infof does nothing.
func (nopLogger) Infof(string, ...any) {}

// Warnf does nothing.
func (nopLogger) Warnf(string, ...any) {}

// SlogLogger returns a Logger that forwards to *slog.Logger. Each
// Debugf/Infof/Warnf call formats the message with fmt.Sprintf and
// writes it under slog's "msg" attribute. Use this when the host app
// already centralizes structured logging through slog.
//
// The slog logger's full attribute pipeline runs as usual, so any
// handler-level attributes (group, service name, request ID) attach
// to every cipher event. Passing a nil *slog.Logger panics; pass the
// global slog.Default() to use the process default.
func SlogLogger(log *slog.Logger) Logger {
	if log == nil {
		panic("cipher: SlogLogger: nil *slog.Logger")
	}
	return &slogAdapter{log: log}
}

// slogAdapter bridges Logger calls onto a *slog.Logger.
type slogAdapter struct {
	log *slog.Logger
}

// Debugf logs at DEBUG via the wrapped slog.Logger.
func (s *slogAdapter) Debugf(format string, args ...any) {
	s.logAt(slog.LevelDebug, format, args...)
}

// Infof logs at INFO via the wrapped slog.Logger.
func (s *slogAdapter) Infof(format string, args ...any) {
	s.logAt(slog.LevelInfo, format, args...)
}

// Warnf logs at WARN via the wrapped slog.Logger.
func (s *slogAdapter) Warnf(format string, args ...any) {
	s.logAt(slog.LevelWarn, format, args...)
}

// logAt emits a record at the given level.
func (s *slogAdapter) logAt(level slog.Level, format string, args ...any) {
	if !s.log.Enabled(context.Background(), level) {
		return
	}
	s.log.Log(context.Background(), level, fmt.Sprintf(format, args...))
}
