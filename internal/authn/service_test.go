package authn

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
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
	ceremony, err := service.BeginRegistration(context.Background(), code, "Windows workstation", now)
	if err != nil {
		t.Fatal(err)
	}
	if ceremony.CeremonyID == "" || ceremony.PublicKey == nil {
		t.Fatal("expected registration ceremony")
	}
	if _, err := service.BeginRegistration(context.Background(), "wrong-code", "Test", now); !errors.Is(err, storage.ErrBootstrapInvalid) {
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
	if session.ExpiresAt.Sub(now) != 30*24*time.Hour {
		t.Fatalf("unexpected trusted session duration: %s", session.ExpiresAt.Sub(now))
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

func TestBootstrapRemainsAvailableForLocalRecovery(t *testing.T) {
	_, store := testService(t)
	defer store.Close()
	now := time.Now().UTC()
	if _, err := store.EnsureAuthUser(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	if err := store.AddAuthCredential(context.Background(), []byte("existing"), []byte("encrypted"), "Existing passkey", now); err != nil {
		t.Fatal(err)
	}
	if err := store.DeleteAuthCredential(context.Background(), []byte("existing")); !errors.Is(err, storage.ErrFinalAuthCredential) {
		t.Fatalf("expected final passkey protection, got %v", err)
	}
	if err := store.AddAuthCredential(context.Background(), []byte("replacement"), []byte("encrypted"), "Replacement", now); err != nil {
		t.Fatal(err)
	}
	if err := store.DeleteAuthCredential(context.Background(), []byte("existing")); err != nil {
		t.Fatal(err)
	}
	code, err := CreateBootstrap(context.Background(), store, 10*time.Minute, now)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte(code))
	valid, err := store.BootstrapValid(context.Background(), digest[:], now)
	if err != nil || !valid {
		t.Fatalf("expected recovery bootstrap to be valid: %v", err)
	}
}

func TestReauthorizationGrantIsScopedAndSingleUse(t *testing.T) {
	service, store := testService(t)
	defer store.Close()
	now := time.Now().UTC()
	token := "reauthorization-token"
	session := "session-token"
	tokenHash := sha256.Sum256([]byte(token))
	sessionHash := sha256.Sum256([]byte(session))
	service.grants[base64.RawURLEncoding.EncodeToString(tokenHash[:])] = authorizationGrant{sessionHash: sessionHash, scope: "action:defender-quick-scan", expiresAt: now.Add(time.Minute)}
	if err := service.ConsumeReauthorization(session, token, "action:defender-signature-update", now); !errors.Is(err, ErrReauthorization) {
		t.Fatalf("expected scope rejection, got %v", err)
	}
	service.grants[base64.RawURLEncoding.EncodeToString(tokenHash[:])] = authorizationGrant{sessionHash: sessionHash, scope: "action:defender-quick-scan", expiresAt: now.Add(time.Minute)}
	if err := service.ConsumeReauthorization(session, token, "action:defender-quick-scan", now); err != nil {
		t.Fatal(err)
	}
	if err := service.ConsumeReauthorization(session, token, "action:defender-quick-scan", now); !errors.Is(err, ErrReauthorization) {
		t.Fatalf("expected single-use rejection, got %v", err)
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
