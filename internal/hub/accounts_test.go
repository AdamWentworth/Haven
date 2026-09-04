package hub

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const accountProfileJSON = `{
	"provider":"Google",
	"label":"Personal account",
	"identifier":"owner@example.com",
	"category":"email",
	"twoStepStatus":"disabled",
	"factors":[],
	"passwordStatus":"unique",
	"recoveryStatus":"configured",
	"backupCodesStatus":"missing",
	"lastReviewedAt":"2026-09-04T12:00:00Z",
	"notes":"Review this profile directly at Google."
}`

func TestAccountNotebookCRUDAndPrivacyBoundary(t *testing.T) {
	server, store := testServer(t)
	defer store.Close()

	created := httptest.NewRecorder()
	server.Handler().ServeHTTP(created, httptest.NewRequest(http.MethodPost, "/api/account-profiles", strings.NewReader(accountProfileJSON)))
	if created.Code != http.StatusOK {
		t.Fatalf("create returned HTTP %d: %s", created.Code, created.Body.String())
	}
	var profile struct {
		ID          string `json:"id"`
		Provider    string `json:"provider"`
		Status      string `json:"status"`
		Suggestions []struct {
			ID string `json:"id"`
		} `json:"suggestions"`
	}
	if err := json.NewDecoder(created.Body).Decode(&profile); err != nil {
		t.Fatal(err)
	}
	if profile.ID == "" || profile.Provider != "Google" || profile.Status != "attention" || len(profile.Suggestions) == 0 || profile.Suggestions[0].ID != "enable-two-step" {
		t.Fatalf("unexpected created profile: %#v", profile)
	}

	listed := httptest.NewRecorder()
	server.Handler().ServeHTTP(listed, httptest.NewRequest(http.MethodGet, "/api/account-profiles", nil))
	if listed.Code != http.StatusOK || !strings.Contains(listed.Body.String(), `"identifier":"owner@example.com"`) {
		t.Fatalf("list returned HTTP %d: %s", listed.Code, listed.Body.String())
	}
	if listed.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("private notebook response must not be cached")
	}

	audit, err := store.ListAudit(t.Context(), 10)
	if err != nil || len(audit) != 1 {
		t.Fatalf("unexpected audit records: %#v, %v", audit, err)
	}
	if strings.Contains(audit[0].Detail, "Google") || strings.Contains(audit[0].Detail, "owner@example.com") || strings.Contains(audit[0].Detail, "Review this") {
		t.Fatalf("audit history exposed account content: %#v", audit[0])
	}

	removed := httptest.NewRecorder()
	server.Handler().ServeHTTP(removed, httptest.NewRequest(http.MethodPost, "/api/account-profiles/"+profile.ID+"/remove", nil))
	if removed.Code != http.StatusNoContent {
		t.Fatalf("remove returned HTTP %d: %s", removed.Code, removed.Body.String())
	}
}

func TestAccountNotebookRejectsUnknownAndSecretFields(t *testing.T) {
	server, store := testServer(t)
	defer store.Close()

	unknown := httptest.NewRecorder()
	server.Handler().ServeHTTP(unknown, httptest.NewRequest(http.MethodPost, "/api/account-profiles", strings.NewReader(strings.TrimSuffix(accountProfileJSON, "}")+`,"password":"not-allowed"}`)))
	if unknown.Code != http.StatusBadRequest {
		t.Fatalf("unknown secret field returned HTTP %d: %s", unknown.Code, unknown.Body.String())
	}

	obviousSecret := strings.Replace(accountProfileJSON, "Review this profile directly at Google.", "otpauth://totp/secret-material", 1)
	rejected := httptest.NewRecorder()
	server.Handler().ServeHTTP(rejected, httptest.NewRequest(http.MethodPost, "/api/account-profiles", strings.NewReader(obviousSecret)))
	if rejected.Code != http.StatusBadRequest || !strings.Contains(rejected.Body.String(), "Do not enter passwords") {
		t.Fatalf("obvious secret returned HTTP %d: %s", rejected.Code, rejected.Body.String())
	}
}

func TestDemoAccountNotebookUsesOnlySyntheticProfiles(t *testing.T) {
	server, store := testServer(t)
	defer store.Close()
	server.demoMode = true

	listed := httptest.NewRecorder()
	server.Handler().ServeHTTP(listed, httptest.NewRequest(http.MethodGet, "/api/account-profiles", nil))
	if listed.Code != http.StatusOK || !strings.Contains(listed.Body.String(), `"id":"acct_demo_`) || strings.Contains(listed.Body.String(), "owner@example.com") {
		t.Fatalf("unexpected demo notebook: %d %s", listed.Code, listed.Body.String())
	}
	mutated := httptest.NewRecorder()
	server.Handler().ServeHTTP(mutated, httptest.NewRequest(http.MethodPost, "/api/account-profiles", strings.NewReader(accountProfileJSON)))
	if mutated.Code != http.StatusNotImplemented {
		t.Fatalf("demo profile mutation returned HTTP %d", mutated.Code)
	}
}
