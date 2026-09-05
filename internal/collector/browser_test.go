package collector

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/AdamWentworth/haven/internal/model"
)

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
