package workspace

import (
	"context"
	"errors"
	"testing"

	"github.com/KLORQ/quarshell-core/domain"
	"github.com/KLORQ/quarshell-gateway/internal/application/lifecycle"
)

func testService(t *testing.T) (*Service, *lifecycle.MemoryStore) {
	t.Helper()
	store := lifecycle.NewMemoryStore()
	service, err := NewService(store)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	return service, store
}

func createRequest() CreateRequest {
	return CreateRequest{ID: "ws", Name: "Workspace", Owner: "alice", IdempotencyKey: "create"}
}

func TestWorkspaceCreateIsIdempotent(t *testing.T) {
	service, store := testService(t)
	first, replayed, err := service.Create(context.Background(), createRequest())
	if err != nil || replayed || first.Name != "Workspace" {
		t.Fatalf("Create = %+v replayed=%v err=%v", first, replayed, err)
	}
	second, replayed, err := service.Create(context.Background(), createRequest())
	if err != nil || !replayed || second.ID != first.ID {
		t.Fatalf("replay = %+v replayed=%v err=%v", second, replayed, err)
	}
	if err := store.View(context.Background(), func(tx lifecycle.ReadTx) error {
		if tx.PendingOutbox() != 1 {
			t.Fatalf("outbox = %d", tx.PendingOutbox())
		}
		return nil
	}); err != nil {
		t.Fatalf("View: %v", err)
	}
}

func TestWorkspaceMembersAndAuthorization(t *testing.T) {
	service, _ := testService(t)
	if _, _, err := service.Create(context.Background(), createRequest()); err != nil {
		t.Fatalf("Create: %v", err)
	}
	for subject, role := range map[string]Role{"bob": RoleAdmin, "carol": RoleMember, "dave": RoleViewer} {
		if _, _, err := service.AddMember(context.Background(), "ws", subject, role, domain.OperationID("add-"+subject)); err != nil {
			t.Fatalf("AddMember %s: %v", subject, err)
		}
	}
	members, err := service.ListMembers(context.Background(), "ws")
	if err != nil || len(members) != 4 {
		t.Fatalf("members = %+v err=%v", members, err)
	}
	// Owner and admin can manage; member cannot.
	if err := service.Authorize(context.Background(), "ws", "alice", ActionManage); err != nil {
		t.Fatalf("owner manage: %v", err)
	}
	if err := service.Authorize(context.Background(), "ws", "bob", ActionManage); err != nil {
		t.Fatalf("admin manage: %v", err)
	}
	if err := service.Authorize(context.Background(), "ws", "carol", ActionManage); !errors.Is(err, domain.ErrPermissionDenied) {
		t.Fatalf("member manage = %v", err)
	}
	if err := service.Authorize(context.Background(), "ws", "carol", ActionWrite); err != nil {
		t.Fatalf("member write: %v", err)
	}
	if err := service.Authorize(context.Background(), "ws", "dave", ActionWrite); !errors.Is(err, domain.ErrPermissionDenied) {
		t.Fatalf("viewer write = %v", err)
	}
	if err := service.Authorize(context.Background(), "ws", "dave", ActionRead); err != nil {
		t.Fatalf("viewer read: %v", err)
	}
	if err := service.Authorize(context.Background(), "ws", "eve", ActionRead); !errors.Is(err, domain.ErrPermissionDenied) {
		t.Fatalf("non-member read = %v", err)
	}
}

func TestWorkspaceRemoveMemberAndDelete(t *testing.T) {
	service, _ := testService(t)
	if _, _, err := service.Create(context.Background(), createRequest()); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, _, err := service.AddMember(context.Background(), "ws", "bob", RoleViewer, "add-bob"); err != nil {
		t.Fatalf("AddMember: %v", err)
	}
	if err := service.RemoveMember(context.Background(), "ws", "bob", "remove-bob"); err != nil {
		t.Fatalf("RemoveMember: %v", err)
	}
	if err := service.Authorize(context.Background(), "ws", "bob", ActionRead); !errors.Is(err, domain.ErrPermissionDenied) {
		t.Fatalf("removed member = %v", err)
	}
	if err := service.Delete(context.Background(), "ws", "delete"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := service.Get(context.Background(), "ws"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("Get after delete = %v", err)
	}
	if members, err := service.ListMembers(context.Background(), "ws"); err != nil || len(members) != 0 {
		t.Fatalf("members after delete = %+v %v", members, err)
	}
}

func TestWorkspaceReplayAfterRestart(t *testing.T) {
	service, store := testService(t)
	if _, _, err := service.Create(context.Background(), createRequest()); err != nil {
		t.Fatalf("Create: %v", err)
	}
	restarted, _ := NewService(store)
	result, replayed, err := restarted.Create(context.Background(), createRequest())
	if err != nil || !replayed || result.ID != "ws" {
		t.Fatalf("replay = %+v replayed=%v err=%v", result, replayed, err)
	}
	list, err := restarted.List(context.Background())
	if err != nil || len(list) != 1 {
		t.Fatalf("List = %+v %v", list, err)
	}
}
