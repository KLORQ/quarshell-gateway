package lifecycle

import (
	"context"
	"time"

	"github.com/KLORQ/quarshell-core/domain"
)

// Coordinator executes one idempotent operation per key. The entity updates and
// the operation record commit in the same transaction, so a crash cannot leave
// a mutation without its replay record.
type Coordinator struct {
	Store Store
	Now   func() time.Time
}

// Execute returns the recorded result for a repeated key and hash. A different
// hash for the same key is a conflict.
func (c *Coordinator) Execute(ctx context.Context, key, requestHash string, fn func(WriteTx) ([]byte, error)) ([]byte, bool, error) {
	if c.Store == nil {
		return nil, false, domain.Invalidf("lifecycle.execute", "store is required")
	}
	if key == "" || requestHash == "" {
		return nil, false, domain.Invalidf("lifecycle.execute", "key and request hash are required")
	}
	if fn == nil {
		return nil, false, domain.Invalidf("lifecycle.execute", "operation callback is required")
	}
	var result []byte
	replayed := false
	err := c.Store.Update(ctx, func(tx WriteTx) error {
		existing, exists, err := tx.GetOperation(key)
		if err != nil {
			return err
		}
		if exists {
			if existing.RequestHash != requestHash {
				return domain.New(domain.CodeConflict, "lifecycle.execute", "operation key reused with a different request")
			}
			result = append([]byte(nil), existing.Result...)
			replayed = true
			return nil
		}
		value, err := fn(tx)
		if err != nil {
			return err
		}
		result = append([]byte(nil), value...)
		createdAt := time.Now()
		if c.Now != nil {
			createdAt = c.Now()
		}
		return tx.PutOperation(Operation{Key: key, RequestHash: requestHash, Result: value, CreatedAt: createdAt})
	})
	if err != nil {
		return nil, false, err
	}
	return result, replayed, nil
}
