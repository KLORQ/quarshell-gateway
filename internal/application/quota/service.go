// Package quota implements workspace resource quotas.
package quota

import (
	"context"
	"encoding/json"
	"strconv"
	"time"

	"github.com/KLORQ/quarshell-core/domain"
	"github.com/KLORQ/quarshell-gateway/internal/application/lifecycle"
)

const quotaKind = "quota"

// Limits are workspace resource ceilings. Zero means unlimited.
type Limits struct {
	CPU          int64 `json:"cpu"`
	MemoryBytes  int64 `json:"memory_bytes"`
	Sandboxes    int64 `json:"sandboxes"`
	StorageBytes int64 `json:"storage_bytes"`
}

// Quota is the durable workspace quota.
type Quota struct {
	Workspace domain.WorkspaceID `json:"workspace"`
	Limits    Limits             `json:"limits"`
	Version   uint64             `json:"version"`
	UpdatedAt time.Time          `json:"updated_at"`
}

// Service owns quotas.
type Service struct {
	store lifecycle.Store
	now   func() time.Time
}

// NewService returns a quota service.
func NewService(store lifecycle.Store) (*Service, error) {
	if store == nil {
		return nil, domain.Invalidf("quota.service", "store is required")
	}
	return &Service{store: store, now: time.Now}, nil
}

// Set creates or updates a quota with optimistic concurrency.
func (s *Service) Set(ctx context.Context, workspace domain.WorkspaceID, limits Limits, expectedVersion uint64) (Quota, error) {
	if !workspace.Valid() {
		return Quota{}, domain.Invalidf("quota.set", "workspace is required")
	}
	if limits.CPU < 0 || limits.MemoryBytes < 0 || limits.Sandboxes < 0 || limits.StorageBytes < 0 {
		return Quota{}, domain.Invalidf("quota.set", "quota limits must not be negative")
	}
	var result Quota
	err := s.store.Update(ctx, func(tx lifecycle.WriteTx) error {
		current, exists, err := tx.Get(quotaKind, string(workspace))
		if err != nil {
			return err
		}
		version := expectedVersion
		if expectedVersion == 0 {
			if exists {
				return domain.New(domain.CodeConflict, "quota.set", "quota already exists")
			}
		} else if !exists || current.Version != expectedVersion {
			return domain.New(domain.CodeConflict, "quota.set", "quota version conflict")
		}
		quota := Quota{Workspace: workspace, Limits: limits, Version: version + 1, UpdatedAt: s.now().UTC()}
		payload, err := json.Marshal(quota)
		if err != nil {
			return err
		}
		if _, err := tx.Put(quotaKind, string(workspace), version, payload); err != nil {
			return err
		}
		if err := tx.Enqueue(lifecycle.OutboxMessage{ID: string(workspace) + ":quota:" + strconv.FormatUint(quota.Version, 10), Topic: "quota.updated", Payload: payload}); err != nil {
			return err
		}
		result = quota
		return nil
	})
	return result, err
}

// Get returns a workspace quota.
func (s *Service) Get(ctx context.Context, workspace domain.WorkspaceID) (Quota, bool, error) {
	var quota Quota
	found := false
	err := s.store.View(ctx, func(tx lifecycle.ReadTx) error {
		record, exists, err := tx.Get(quotaKind, string(workspace))
		if err != nil {
			return err
		}
		if !exists {
			return nil
		}
		found = true
		return json.Unmarshal(record.Payload, &quota)
	})
	return quota, found, err
}

// Check fails when usage exceeds a configured limit.
func (s *Service) Check(ctx context.Context, workspace domain.WorkspaceID, usage Limits) error {
	quota, found, err := s.Get(ctx, workspace)
	if err != nil {
		return err
	}
	if !found {
		return nil
	}
	if quota.Limits.CPU > 0 && usage.CPU > quota.Limits.CPU {
		return quotaError("cpu")
	}
	if quota.Limits.MemoryBytes > 0 && usage.MemoryBytes > quota.Limits.MemoryBytes {
		return quotaError("memory")
	}
	if quota.Limits.Sandboxes > 0 && usage.Sandboxes > quota.Limits.Sandboxes {
		return quotaError("sandboxes")
	}
	if quota.Limits.StorageBytes > 0 && usage.StorageBytes > quota.Limits.StorageBytes {
		return quotaError("storage")
	}
	return nil
}

func quotaError(resource string) error {
	return domain.New(domain.CodeConflict, "quota.check", "quota exceeded for "+resource)
}
