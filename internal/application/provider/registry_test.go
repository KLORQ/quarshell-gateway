package provider

import (
	"context"
	"errors"
	"testing"

	"github.com/KLORQ/quarshell-core/domain"
	"github.com/KLORQ/quarshell-gateway/internal/application/lifecycle"
)

func TestProviderRegistryLifecycle(t *testing.T) {
	registry, err := NewRegistry(lifecycle.NewMemoryStore())
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	ctx := context.Background()
	created, replayed, err := registry.Create(ctx, CreateRequest{
		ID: "api", Name: "API", Driver: "openai", Config: []byte(`{"base_url":"https://api.example.com"}`),
		Profiles: []ProfileInput{{ID: "default", Name: "Default", Config: []byte(`{"model":"gpt"}`)}}, IdempotencyKey: "create-api",
	})
	if err != nil || replayed || created.Revision != 1 {
		t.Fatalf("Create = %+v replayed=%v err=%v", created, replayed, err)
	}
	again, replayed, err := registry.Create(ctx, CreateRequest{
		ID: "api", Name: "API", Driver: "openai", Config: []byte(`{"base_url":"https://api.example.com"}`),
		Profiles: []ProfileInput{{ID: "default", Name: "Default", Config: []byte(`{"model":"gpt"}`)}}, IdempotencyKey: "create-api",
	})
	if err != nil || !replayed || again.Revision != 1 {
		t.Fatalf("Create replay = %+v replayed=%v err=%v", again, replayed, err)
	}
	profiles, err := registry.ListProfiles(ctx, "api")
	if err != nil || len(profiles) != 1 || profiles[0].ID != "default" {
		t.Fatalf("ListProfiles = %+v err=%v", profiles, err)
	}
	updated, err := registry.Update(ctx, UpdateRequest{ID: "api", Name: "API v2", Driver: "openai", Config: []byte(`{}`), ExpectedRevision: 1})
	if err != nil || updated.Revision != 2 || updated.Name != "API v2" {
		t.Fatalf("Update = %+v err=%v", updated, err)
	}
	if _, err := registry.Update(ctx, UpdateRequest{ID: "api", Name: "stale", Driver: "openai", ExpectedRevision: 1}); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("stale update = %v", err)
	}
	imported, replayed, err := registry.ImportProfiles(ctx, "api", []ProfileInput{
		{ID: "default", Name: "Default v2", Config: []byte(`{"model":"gpt-2"}`)},
		{ID: "fast", Name: "Fast"},
	}, "import-1")
	if err != nil || replayed || len(imported) != 2 {
		t.Fatalf("ImportProfiles = %+v replayed=%v err=%v", imported, replayed, err)
	}
	if imported[0].Revision != 2 {
		t.Fatalf("profile revision = %d", imported[0].Revision)
	}
	if err := registry.DeleteProfile(ctx, "api", "fast", "delete-fast"); err != nil {
		t.Fatalf("DeleteProfile: %v", err)
	}
	if _, err := registry.GetProfile(ctx, "api", "fast"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("GetProfile after delete = %v", err)
	}
	if err := registry.Delete(ctx, "api", "delete-api"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := registry.Get(ctx, "api"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("Get after delete = %v", err)
	}
}

func TestProviderRegistryLint(t *testing.T) {
	registry, _ := NewRegistry(lifecycle.NewMemoryStore())
	issues, err := registry.LintProfiles(context.Background(), "api", []ProfileInput{
		{ID: "", Name: ""},
		{ID: "a", Name: "A", Config: []byte(`{`)},
		{ID: "a", Name: "A2"},
	})
	if err != nil || len(issues) < 4 {
		t.Fatalf("LintProfiles = %+v err=%v", issues, err)
	}
	if _, _, err := registry.Create(context.Background(), CreateRequest{ID: "api", Name: "API", Driver: "x", Profiles: []ProfileInput{{ID: "a/b", Name: "x"}}}); err == nil {
		t.Fatalf("invalid profile id accepted")
	}
}
