package hub

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/AdamWentworth/haven/internal/model"
)

const browserReviewBody = `{"deviceId":"test-device","browserId":"chrome","profileFingerprint":"abcdef0123456789abcdef01","domain":"accounts.example.test","state":"signed-in-keep"}`

func TestBrowserSiteReviewCRUDAndAuditPrivacy(t *testing.T) {
	server, store := testServer(t)
	defer store.Close()
	snapshot := server.collector.Collect(context.Background())
	snapshot.BrowserSecurity = &model.BrowserSecurityStatus{Coverage: "observed", Browsers: []model.BrowserInstallation{{ID: "chrome", Name: "Google Chrome", ProfileCount: 1, Profiles: []model.BrowserProfile{{Fingerprint: "abcdef0123456789abcdef01", Name: "Personal", CookieStatus: "observed", CookieCount: 1, Sites: []model.BrowserCookieSite{{Domain: "accounts.example.test", CookieCount: 1, PersistentCookieCount: 1}}}}, Extensions: []model.BrowserExtension{}}}}
	if err := store.SaveSnapshot(context.Background(), snapshot); err != nil {
		t.Fatal(err)
	}

	save := httptest.NewRecorder()
	server.Handler().ServeHTTP(save, httptest.NewRequest(http.MethodPost, "/api/browser-site-reviews", strings.NewReader(browserReviewBody)))
	if save.Code != http.StatusOK || !strings.Contains(save.Body.String(), `"state":"signed-in-keep"`) {
		t.Fatalf("unexpected save response: %d %s", save.Code, save.Body.String())
	}

	list := httptest.NewRecorder()
	server.Handler().ServeHTTP(list, httptest.NewRequest(http.MethodGet, "/api/browser-site-reviews?deviceId=test-device", nil))
	if list.Code != http.StatusOK || !strings.Contains(list.Body.String(), `"domain":"accounts.example.test"`) {
		t.Fatalf("unexpected list response: %d %s", list.Code, list.Body.String())
	}
	if list.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("browser site reviews must not be cached")
	}

	audit, err := store.ListAudit(context.Background(), 10)
	if err != nil || len(audit) == 0 {
		t.Fatalf("browser review audit was not written: %#v %v", audit, err)
	}
	if strings.Contains(audit[0].Target, "accounts.example.test") || strings.Contains(audit[0].Detail, "accounts.example.test") {
		t.Fatal("browser domain leaked into audit history")
	}

	removeBody := `{"deviceId":"test-device","browserId":"chrome","profileFingerprint":"abcdef0123456789abcdef01","domain":"accounts.example.test"}`
	remove := httptest.NewRecorder()
	server.Handler().ServeHTTP(remove, httptest.NewRequest(http.MethodPost, "/api/browser-site-reviews/remove", strings.NewReader(removeBody)))
	if remove.Code != http.StatusNoContent {
		t.Fatalf("unexpected remove response: %d %s", remove.Code, remove.Body.String())
	}
	list = httptest.NewRecorder()
	server.Handler().ServeHTTP(list, httptest.NewRequest(http.MethodGet, "/api/browser-site-reviews?deviceId=test-device", nil))
	if list.Code != http.StatusOK || strings.Contains(list.Body.String(), "accounts.example.test") {
		t.Fatalf("removed review remained visible: %d %s", list.Code, list.Body.String())
	}
}

func TestBrowserSiteReviewRejectsUnboundedOrUnknownInput(t *testing.T) {
	server, store := testServer(t)
	defer store.Close()
	cases := []string{
		`{"deviceId":"test-device","browserId":"chrome","profileFingerprint":"abcdef0123456789abcdef01","domain":"accounts.example.test","state":"protect-everything"}`,
		`{"deviceId":"test-device","browserId":"chrome","profileFingerprint":"abcdef0123456789abcdef01","domain":"https://example.test/path","state":"signed-in-keep"}`,
		`{"deviceId":"test-device","browserId":"chrome","profileFingerprint":"abcdef0123456789abcdef01","domain":"accounts.example.test","state":"signed-in-keep","cookieValue":"private-session-token"}`,
	}
	for _, body := range cases {
		response := httptest.NewRecorder()
		server.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/api/browser-site-reviews", strings.NewReader(body)))
		if response.Code != http.StatusBadRequest {
			t.Fatalf("invalid browser review returned HTTP %d: %s", response.Code, response.Body.String())
		}
	}
}

func TestBrowserSiteReviewRequiresCurrentLiveEvidence(t *testing.T) {
	server, store := testServer(t)
	defer store.Close()
	if err := store.SaveSnapshot(context.Background(), server.collector.Collect(context.Background())); err != nil {
		t.Fatal(err)
	}

	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/api/browser-site-reviews", strings.NewReader(browserReviewBody)))
	if response.Code != http.StatusConflict {
		t.Fatalf("unobserved browser review returned HTTP %d: %s", response.Code, response.Body.String())
	}
}
