package cipher

// Logger is the minimal logging contract cipher uses for observability.
// It is satisfied by zap.SugaredLogger, logrus.Logger, and any other
// logger exposing Printf-style methods at three severity levels.
//
// Logger calls are made at the boundaries of encode/decode operations.
// They are best-effort and do not affect functional behavior.
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
