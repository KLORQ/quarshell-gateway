// Package settings implements durable workspace-scoped settings.
package settings

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"github.com/KLORQ/quarshell-core/domain"
	"github.com/KLORQ/quarshell-gateway/internal/application/lifecycle"
)

const settingKind = "setting"

// Setting is one versioned workspace setting.
type Setting struct {
	Workspace domain.WorkspaceID `json:"workspace"`
	Key       string             `json:"key"`
	Value     []byte             `json:"value"`
	Version   uint64             `json:"version"`
	UpdatedAt time.Time          `json:"updated_at"`
}

// Service owns settings mutations.
type Service struct {
	store       lifecycle.Store
	coordinator *lifecycle.Coordinator
	now         func() time.Time
}

// NewService returns a settings service.
func NewService(store lifecycle.Store) (*Service, error) {
	if store == nil {
		return nil, domain.Invalidf("settings.service", "store is required")
	}
	return &Service{store: store, coordinator: &lifecycle.Coordinator{Store: store}, now: time.Now}, nil
}

// Set creates or updates a setting with optimistic concurrency.
func (s *Service) Set(ctx context.Context, workspace domain.WorkspaceID, key string, value []byte, expectedVersion uint64, idempotencyKey domain.OperationID) (Setting, bool, error) {
	if !workspace.Valid() || strings.TrimSpace(key) == "" || strings.Contains(key, "/") {
		return Setting{}, false, domain.Invalidf("settings.set", "workspace and key are required")
	}
	hash := digest(key + ":" + strconv.FormatUint(expectedVersion, 10) + ":" + digest(string(value)))
	operationKey := strings.TrimSpace(string(idempotencyKey))
	if operationKey == "" {
		operationKey = "settings.set:" + string(workspace) + ":" + key + ":" + hash[:16]
	} else {
		operationKey = "settings.set:" + operationKey
	}
	now := s.now().UTC()
	result, replayed, err := s.coordinator.Execute(ctx, operationKey, hash, func(tx lifecycle.WriteTx) ([]byte, error) {
		current, exists, err := tx.Get(settingKind, settingID(workspace, key))
		if err != nil {
			return nil, err
		}
		version := expectedVersion
		if expectedVersion == 0 {
			if exists {
				return nil, domain.New(domain.CodeConflict, "settings.set", "setting already exists")
			}
			version = 0
		} else if !exists || current.Version != expectedVersion {
			return nil, domain.New(domain.CodeConflict, "settings.set", "setting version conflict")
		}
		setting := Setting{Workspace: workspace, Key: key, Value: append([]byte(nil), value...), Version: version + 1, UpdatedAt: now}
		payload, err := json.Marshal(setting)
		if err != nil {
			return nil, err
		}
		if _, err := tx.Put(settingKind, settingID(workspace, key), version, payload); err != nil {
			return nil, err
		}
		if err := tx.Enqueue(lifecycle.OutboxMessage{ID: settingID(workspace, key) + ":updated:" + strconv.FormatUint(setting.Version, 10), Topic: "setting.updated", Payload: payload}); err != nil {
			return nil, err
		}
		return payload, nil
	})
	if err != nil {
		return Setting{}, false, err
	}
	var setting Setting
	if err := json.Unmarshal(result, &setting); err != nil {
		return Setting{}, false, err
	}
	return setting, replayed, nil
}

// Get returns one setting.
func (s *Service) Get(ctx context.Context, workspace domain.WorkspaceID, key string) (Setting, error) {
	var setting Setting
	err := s.store.View(ctx, func(tx lifecycle.ReadTx) error {
		record, exists, err := tx.Get(settingKind, settingID(workspace, key))
		if err != nil {
			return err
		}
		if !exists {
			return domain.Wrap(domain.ErrNotFound, "settings.get", "setting not found")
		}
		return json.Unmarshal(record.Payload, &setting)
	})
	return setting, err
}

// List returns settings for one workspace sorted by key.
func (s *Service) List(ctx context.Context, workspace domain.WorkspaceID) ([]Setting, error) {
	var result []Setting
	err := s.store.View(ctx, func(tx lifecycle.ReadTx) error {
		records, err := tx.List(settingKind)
		if err != nil {
			return err
		}
		prefix := string(workspace) + "/"
		for _, record := range records {
			if !strings.HasPrefix(record.ID, prefix) {
				continue
			}
			var setting Setting
			if err := json.Unmarshal(record.Payload, &setting); err != nil {
				return err
			}
			result = append(result, setting)
		}
		return nil
	})
	return result, err
}

// Delete removes a setting idempotently.
func (s *Service) Delete(ctx context.Context, workspace domain.WorkspaceID, key string, idempotencyKey domain.OperationID) error {
	operationKey := strings.TrimSpace(string(idempotencyKey))
	if operationKey == "" {
		operationKey = "settings.delete:" + string(workspace) + ":" + key
	} else {
		operationKey = "settings.delete:" + operationKey
	}
	_, _, err := s.coordinator.Execute(ctx, operationKey, digest(string(workspace)+"/"+key), func(tx lifecycle.WriteTx) ([]byte, error) {
		record, exists, err := tx.Get(settingKind, settingID(workspace, key))
		if err != nil {
			return nil, err
		}
		if !exists {
			return []byte(`{}`), nil
		}
		if err := tx.Delete(settingKind, settingID(workspace, key), record.Version); err != nil {
			return nil, err
		}
		if err := tx.Enqueue(lifecycle.OutboxMessage{ID: operationKey + ":removed", Topic: "setting.deleted", Payload: record.Payload}); err != nil {
			return nil, err
		}
		return []byte(`{}`), nil
	})
	return err
}

func settingID(workspace domain.WorkspaceID, key string) string {
	return string(workspace) + "/" + key
}

func digest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}
