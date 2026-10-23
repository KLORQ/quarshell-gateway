package sandboxlogs

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/KLORQ/quarshell-core/domain"
	"github.com/KLORQ/quarshell-gateway/internal/application/lifecycle"
)

const (
	cursorEpochRecordKind = "sandbox_log_cursor_epoch"
	cursorEpochRecordID   = "gateway"
)

type cursorEpochRecord struct {
	Epoch string `json:"epoch"`
}

// CursorEpoch returns the durable cursor namespace shared by Gateway servers
// that use the same lifecycle store. It is created atomically on first use.
func (s *Service) CursorEpoch(ctx context.Context) (string, error) {
	if s == nil || s.store == nil || ctx == nil {
		return "", fmt.Errorf("sandbox logs: cursor epoch requires a service, store, and context")
	}
	for attempt := 0; attempt < 8; attempt++ {
		var epoch string
		err := s.store.Update(ctx, func(tx lifecycle.WriteTx) error {
			record, exists, err := tx.Get(cursorEpochRecordKind, cursorEpochRecordID)
			if err != nil {
				return err
			}
			if exists {
				var stored cursorEpochRecord
				if err := json.Unmarshal(record.Payload, &stored); err != nil || len(stored.Epoch) != 32 {
					return fmt.Errorf("sandbox logs: stored cursor epoch is invalid")
				}
				epoch = stored.Epoch
				return nil
			}
			var raw [16]byte
			if _, err := rand.Read(raw[:]); err != nil {
				return fmt.Errorf("sandbox logs: generate cursor epoch: %w", err)
			}
			epoch = hex.EncodeToString(raw[:])
			payload, err := json.Marshal(cursorEpochRecord{Epoch: epoch})
			if err != nil {
				return fmt.Errorf("sandbox logs: encode cursor epoch: %w", err)
			}
			_, err = tx.Put(cursorEpochRecordKind, cursorEpochRecordID, 0, payload)
			return err
		})
		if errors.Is(err, domain.ErrConflict) {
			continue
		}
		if err != nil {
			return "", fmt.Errorf("sandbox logs: load cursor epoch: %w", err)
		}
		return epoch, nil
	}
	return "", fmt.Errorf("sandbox logs: cursor epoch creation conflicted repeatedly")
}
