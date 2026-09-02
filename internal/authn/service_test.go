package authn

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/AdamWentworth/haven/internal/storage"
)

func testService(t *testing.T) (*Service, *storage.Store) {
	t.Helper()
	store, err := storage.Open(context.Background(), filepath.Join(t.TempDir(), "haven.db"))
	if err != nil {
		t.Fatal(err)
	}
	service, err := New(store, filepath.Join(t.TempDir(), "auth.key"), "http://localhost:5080")
	if err != nil {
		store.Close()
		t.Fatal(err)
	}
	return service, store
}

func TestBootstrapBeginsResidentPasskeyRegistration(t *testing.T) {
	service, store := testService(t)
	defer store.Close()
	now := time.Now().UTC()
	code, err := CreateBootstrap(context.Background(), store, 10*time.Minute, now)
	if err != nil {
		t.Fatal(err)
	}
	ceremony, err := service.BeginRegistration(context.Background(), code, now)
	if err != nil {
		t.Fatal(err)
	}
	if ceremony.CeremonyID == "" || ceremony.PublicKey == nil {
		t.Fatal("expected registration ceremony")
	}
	if _, err := service.BeginRegistration(context.Background(), "wrong-code", now); !errors.Is(err, storage.ErrBootstrapInvalid) {
		t.Fatalf("expected invalid bootstrap code, got %v", err)
	}
}

func TestSessionsRequireMatchingAntiforgeryToken(t *testing.T) {
	service, store := testService(t)
	defer store.Close()
	now := time.Now().UTC()
	session, err := service.NewSession(context.Background(), now)
	if err != nil {
		t.Fatal(err)
	}
	valid, err := service.ValidateSession(context.Background(), session.Token, now)
	if err != nil || !valid {
		t.Fatalf("expected valid session: %v", err)
	}
	if err := service.ValidateCSRF(context.Background(), session.Token, session.CSRFToken, "different", now); !errors.Is(err, ErrCSRFInvalid) {
		t.Fatalf("expected anti-forgery rejection, got %v", err)
	}
	if err := service.ValidateCSRF(context.Background(), session.Token, session.CSRFToken, session.CSRFToken, now); err != nil {
		t.Fatal(err)
	}
	if err := service.Logout(context.Background(), session.Token); err != nil {
		t.Fatal(err)
	}
	valid, err = service.ValidateSession(context.Background(), session.Token, now)
	if err != nil || valid {
		t.Fatalf("expected logged-out session to be invalid: %v", err)
	}
}

func TestOriginRequiresHTTPSOutsideLocalhost(t *testing.T) {
	store, err := storage.Open(context.Background(), filepath.Join(t.TempDir(), "haven.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, err := New(store, filepath.Join(t.TempDir(), "auth.key"), "http://haven.example.test"); err == nil {
		t.Fatal("expected non-local HTTP origin to be rejected")
	}
}
