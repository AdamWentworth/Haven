package collector

import (
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/AdamWentworth/haven/internal/model"
)

func TestChromiumCookieQueryCannotSelectCredentialColumns(t *testing.T) {
	query := strings.ToLower(chromiumCookieAggregateQuery)
	if strings.Contains(query, "select *") {
		t.Fatal("cookie metadata query must use an explicit projection")
	}
	forbidden := regexp.MustCompile(`\b(?:name|value|encrypted_value|path)\b`)
	if column := forbidden.FindString(query); column != "" {
		t.Fatalf("cookie metadata query selects forbidden credential column %q", column)
	}
}

func TestChromiumCookieInventoryGroupsMetadataWithoutReadingSecrets(t *testing.T) {
	root := t.TempDir()
	profilePath := filepath.Join(root, "Default")
	if err := os.MkdirAll(filepath.Join(profilePath, "Network"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(profilePath, "Preferences"), []byte(`{"profile":{"name":"Your Chrome"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "Local State"), []byte(`{"profile":{"info_cache":{"Default":{"name":"Personal","user_name":"private-address@example.com","gaia_name":"Private Account Name"}}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	database, err := sql.Open("sqlite", filepath.Join(profilePath, "Network", "Cookies"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`CREATE TABLE cookies (
		host_key TEXT, name TEXT, value TEXT, encrypted_value BLOB, path TEXT,
		expires_utc INTEGER, last_access_utc INTEGER, is_secure INTEGER,
		is_httponly INTEGER, is_persistent INTEGER
	)`); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, time.September, 4, 12, 0, 0, 0, time.UTC)
	lastAccess := chromeEpochOffsetMicroseconds + now.UnixMicro()
	expires := chromeEpochOffsetMicroseconds + now.Add(30*24*time.Hour).UnixMicro()
	rows := []struct {
		domain, name, value          string
		persistent, secure, httpOnly int
		expires                      int64
	}{
		{domain: ".facebook.com", name: "c_user", value: "private-account-value", persistent: 1, secure: 1, httpOnly: 1, expires: expires},
		{domain: ".facebook.com", name: "xs", value: "private-session-token", persistent: 0, secure: 1, httpOnly: 1},
		{domain: "accounts.google.com", name: "SID", value: "another-private-token", persistent: 1, secure: 1, httpOnly: 1, expires: expires},
	}
	for _, row := range rows {
		if _, err := database.Exec(`INSERT INTO cookies (host_key, name, value, encrypted_value, path, expires_utc, last_access_utc, is_secure, is_httponly, is_persistent) VALUES (?, ?, ?, ?, '/', ?, ?, ?, ?, ?)`, row.domain, row.name, row.value, []byte("encrypted-secret"), row.expires, lastAccess, row.secure, row.httpOnly, row.persistent); err != nil {
			t.Fatal(err)
		}
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	if _, _, _, _, err := readChromiumCookieMetadata(filepath.Join(profilePath, "Network", "Cookies")); err != nil {
		t.Fatalf("read cookie metadata: %v", err)
	}

	browser, found, partial := scanBrowserRoot(browserRoot{id: "chrome", name: "Google Chrome", kind: "chromium", path: root})
	if !found || partial || len(browser.Profiles) != 1 {
		t.Fatalf("unexpected Chrome profile inventory: %#v, found=%t partial=%t", browser, found, partial)
	}
	profile := browser.Profiles[0]
	if profile.Name != "Personal" || profile.CookieStatus != "observed" || profile.CookieCount != 3 || len(profile.Sites) != 2 {
		t.Fatalf("unexpected cookie metadata: %#v", profile)
	}
	if profile.Sites[0].Domain != "accounts.google.com" && profile.Sites[0].Domain != "facebook.com" {
		t.Fatalf("cookie domains were not normalized: %#v", profile.Sites)
	}
	payload, err := json.Marshal(browser)
	if err != nil {
		t.Fatal(err)
	}
	serialized := string(payload)
	for _, secret := range []string{"c_user", "private-account-value", "xs", "private-session-token", "SID", "another-private-token", "encrypted-secret", "private-address@example.com", "Private Account Name"} {
		if strings.Contains(serialized, secret) {
			t.Fatalf("cookie inventory leaked a cookie name or value %q: %s", secret, serialized)
		}
	}
	if !strings.Contains(serialized, "facebook.com") || !strings.Contains(serialized, "accounts.google.com") {
		t.Fatalf("cookie inventory omitted the requested site metadata: %s", serialized)
	}
}

func TestChromiumInventoryRetainsCapabilitiesWithoutIdentifiersOrHostPatterns(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "Last Version"), []byte("140.0.1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	profile := filepath.Join(root, "Profile 1")
	if err := os.MkdirAll(filepath.Join(profile, "Extensions", "private-extension-id", "1.2.3", "_locales", "en"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(profile, "Preferences"), []byte(`{"never":"read"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	manifest := `{"name":"__MSG_extension_name__","default_locale":"en","version":"1.2.3","permissions":["cookies","history","https://private.example/*"],"optional_permissions":["downloads"],"host_permissions":["<all_urls>"]}`
	manifestPath := filepath.Join(profile, "Extensions", "private-extension-id", "1.2.3", "manifest.json")
	if err := os.WriteFile(manifestPath, []byte(manifest), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(filepath.Dir(manifestPath), "_locales", "en", "messages.json"), []byte(`{"extension_name":{"message":"Password Helper"}}`), 0o600); err != nil {
		t.Fatal(err)
	}

	browser, found, partial := scanBrowserRoot(browserRoot{id: "chrome", name: "Google Chrome", kind: "chromium", path: root})
	if !found || partial || browser.Version != "140.0.1" || browser.ProfileCount != 1 || len(browser.Extensions) != 1 {
		t.Fatalf("unexpected Chromium inventory: %#v, found=%t partial=%t", browser, found, partial)
	}
	extension := browser.Extensions[0]
	if extension.Name != "Password Helper" || extension.Fingerprint == "private-extension-id" || len(extension.Fingerprint) != 24 {
		t.Fatalf("extension identity was not privacy bounded: %#v", extension)
	}
	if extension.SiteAccess != "all-sites" || extension.OptionalSiteAccess != "none-declared" {
		t.Fatalf("host scope was not reduced to a category: %#v", extension)
	}
	if len(extension.SensitivePermissions) != 2 || len(extension.OptionalSensitivePermissions) != 1 {
		t.Fatalf("sensitive permissions were not normalized: %#v", extension)
	}
}

func TestFirefoxInventoryExcludesHiddenComponentsAndRawOrigins(t *testing.T) {
	root := t.TempDir()
	profile := filepath.Join(root, "random.default-release")
	if err := os.MkdirAll(profile, 0o700); err != nil {
		t.Fatal(err)
	}
	state := `{"addons":[{"id":"addon@example","type":"extension","active":true,"hidden":false,"version":"2.0","defaultLocale":{"name":"Review Me"},"userPermissions":{"permissions":["webRequest"],"origins":["https://mail.example/*"]},"optionalPermissions":{"permissions":["cookies"],"origins":["<all_urls>"]}},{"id":"system@example","type":"extension","active":true,"hidden":true,"version":"1","defaultLocale":{"name":"System Component"}}]}`
	if err := os.WriteFile(filepath.Join(profile, "extensions.json"), []byte(state), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(profile, "compatibility.ini"), []byte("[Compatibility]\nLastVersion=139.0_20260101000000/20260101000000\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	browser, found, partial := scanBrowserRoot(browserRoot{id: "firefox", name: "Mozilla Firefox", kind: "firefox", path: root})
	if !found || partial || browser.Version != "139.0" || len(browser.Extensions) != 1 {
		t.Fatalf("unexpected Firefox inventory: %#v", browser)
	}
	extension := browser.Extensions[0]
	if extension.Name != "Review Me" || extension.State != "active" || extension.SiteAccess != "specific-sites" || extension.OptionalSiteAccess != "all-sites" {
		t.Fatalf("unexpected Firefox extension projection: %#v", extension)
	}
}

func TestBrowserInventoryReportsUnreadableRootsWithoutLeakingPaths(t *testing.T) {
	_, found, partial := scanBrowserRoot(browserRoot{id: "chrome", name: "Google Chrome", kind: "chromium", path: filepath.Join(t.TempDir(), "missing")})
	if found || partial {
		t.Fatal("a missing optional browser must not be treated as a collection failure")
	}

	status, notices := collectBrowserSecurity("unsupported")
	if status.Coverage != "unavailable" || len(notices) != 1 || notices[0].Message == "" {
		t.Fatalf("unavailable platform was not represented safely: %#v %#v", status, notices)
	}
}

func TestChromeProtectionsAppearOnlyWhenChromeIsObserved(t *testing.T) {
	snapshot := model.SecuritySnapshot{BrowserSecurity: &model.BrowserSecurityStatus{Coverage: "observed", Protections: []model.BrowserProtectionStatus{
		{ID: "defender-pua", Name: "Potentially unwanted app protection", State: "enabled", Source: "Microsoft Defender preferences"},
		{ID: "chrome-app-bound-encryption", Name: "Chrome App-Bound Encryption policy", State: "default", Source: "Chrome policy"},
	}}}
	t.Setenv("LOCALAPPDATA", t.TempDir())
	t.Setenv("APPDATA", t.TempDir())
	attachBrowserSecurity(&snapshot, "windows")
	if len(snapshot.BrowserSecurity.Protections) != 1 || snapshot.BrowserSecurity.Protections[0].ID != "defender-pua" {
		t.Fatalf("Chrome-only evidence was retained without an observed Chrome installation: %#v", snapshot.BrowserSecurity.Protections)
	}
}

func TestChromiumInventoryUsesNewestNumericVersionDirectory(t *testing.T) {
	root := t.TempDir()
	for _, version := range []string{"1.9.0", "1.10.0"} {
		directory := filepath.Join(root, version)
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
		manifest := `{"name":"Version Test","version":"` + version + `"}`
		if err := os.WriteFile(filepath.Join(directory, "manifest.json"), []byte(manifest), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	manifest, _, err := latestChromiumManifest(root)
	if err != nil || manifest.Version != "1.10.0" {
		t.Fatalf("newest extension version was not selected: %#v, err=%v", manifest, err)
	}
}

func TestChromiumInventoryCountsOnlyPersistentUserProfiles(t *testing.T) {
	root := t.TempDir()
	for _, profile := range []string{"Default", "Profile 2", "Guest Profile", "System Profile", "Not a profile"} {
		directory := filepath.Join(root, profile)
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(directory, "Preferences"), []byte(`{}`), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	browser, found, partial := scanBrowserRoot(browserRoot{id: "chrome", name: "Google Chrome", kind: "chromium", path: root})
	if !found || partial || browser.ProfileCount != 2 {
		t.Fatalf("internal Chromium profiles were counted as owner profiles: %#v", browser)
	}
}

func TestReadBoundedJSONRejectsOversizeAndTrailingValues(t *testing.T) {
	path := filepath.Join(t.TempDir(), "metadata.json")
	if err := os.WriteFile(path, []byte(`{"value":1} {"value":2}`), 0o600); err != nil {
		t.Fatal(err)
	}
	var target map[string]int
	if err := readBoundedJSON(path, 64, &target); err == nil {
		t.Fatal("multiple JSON values were accepted")
	}
	if err := os.WriteFile(path, []byte(`{"value":"`+strings.Repeat("x", 80)+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := readBoundedJSON(path, 64, &target); err == nil {
		t.Fatal("oversized JSON was accepted")
	}
}

func TestBrowserInventorySerializationOmitsRawIdentifiersAndOrigins(t *testing.T) {
	root := t.TempDir()
	profile := filepath.Join(root, "Default")
	extensionID := "private-extension-identifier"
	if err := os.MkdirAll(filepath.Join(profile, "Extensions", extensionID, "1.0.0"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(profile, "Preferences"), []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	origin := "https://private.example/*"
	manifest := `{"name":"Privacy Test","version":"1.0.0","host_permissions":["` + origin + `"]}`
	if err := os.WriteFile(filepath.Join(profile, "Extensions", extensionID, "1.0.0", "manifest.json"), []byte(manifest), 0o600); err != nil {
		t.Fatal(err)
	}
	browser, _, _ := scanBrowserRoot(browserRoot{id: "chrome", name: "Google Chrome", kind: "chromium", path: root})
	payload, err := json.Marshal(browser)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(payload), extensionID) || strings.Contains(string(payload), origin) || strings.Contains(string(payload), "private.example") {
		t.Fatalf("serialized inventory leaked raw browser metadata: %s", payload)
	}
}
