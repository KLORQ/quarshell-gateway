package credentialstore

import (
	"context"
	"errors"

	"github.com/KLORQ/quarshell-core/domain"
)

func classifyContextError(err error) error {
	switch {
	case errors.Is(err, context.Canceled):
		return domain.ErrCanceled
	case errors.Is(err, context.DeadlineExceeded):
		return domain.ErrDeadlineExceeded
	default:
		return err
	}
}
