// Package logger wraps slogx for the quarshell-gateway process.
package logger

import (
	"context"
	"io"
	"log/slog"
	"os"

	"github.com/KLORQ/quarshell-core/slogx"
)

// Options tweak Setup.
type Options struct {
	Service string
	Output  io.Writer
	Level   slog.Level
}

// Setup builds a corporate-masked slogx logger.
func Setup(ctx context.Context, opt Options) *slogx.Logger {
	if opt.Output == nil {
		opt.Output = os.Stderr
	}
	level := opt.Level
	if level == 0 {
		level = slog.LevelInfo
	}
	log := slogx.SetupDefault(
		slogx.WithOutput(opt.Output),
		slogx.WithFormat(slogx.FormatJSON),
		slogx.WithLevel(level),
		slogx.WithCorporateMasking(),
		slogx.WithAddSource(true),
		slogx.WithStackOnError(true),
		slogx.WithTraceContext(true),
		slogx.WithContextKeys(slogx.KeyRequestID, slogx.KeyUserID, slogx.KeyTenantID),
	)
	if opt.Service != "" {
		log = log.With("service", opt.Service)
		slog.SetDefault(log.Logger)
	}
	return log
}

func FromContext(ctx context.Context) *slogx.Logger { return slogx.FromContext(ctx) }
func ToContext(ctx context.Context, log *slogx.Logger) context.Context {
	return slogx.ToContext(ctx, log)
}
