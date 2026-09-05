package sessionwatch

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/AdamWentworth/haven/internal/model"
)

func browserStatus(extension model.BrowserExtension) *model.BrowserSecurityStatus {
	return &model.BrowserSecurityStatus{Coverage: "observed", Browsers: []model.BrowserInstallation{{
		ID: "chrome", Name: "Google Chrome", ProfileCount: 1, Extensions: []model.BrowserExtension{extension},
	}}, Protections: []model.BrowserProtectionStatus{}}
}

func extension() model.BrowserExtension {
	return model.BrowserExtension{
		Fingerprint: "0123456789abcdef01234567", Name: "Example extension", Version: "1.0", State: "installed", ProfileCount: 1,
		SiteAccess: "specific-sites", OptionalSiteAccess: "none-declared", SensitivePermissions: []string{"tabs"}, OptionalSensitivePermissions: []string{},
	}
}

func TestFirstObservationBaselinesSilentlyAndOnlyAfterCommit(t *testing.T) {
	directory := t.TempDir()
	changes, update, err := Prepare(directory, browserStatus(extension()))
	if err != nil || len(changes) != 0 || update == nil {
		t.Fatalf("unexpected first projection: %#v %#v %v", changes, update, err)
	}
	if _, err := os.Stat(filepath.Join(directory, baselineFileName)); !os.IsNotExist(err) {
		t.Fatal("baseline was persisted before an accepted observation")
	}
	if err := update.Commit(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(directory, baselineFileName)); err != nil {
		t.Fatal(err)
	}
}

func TestMeaningfulExtensionChangesAreBoundedAndVersionChangesAreQuiet(t *testing.T) {
	directory := t.TempDir()
	_, initial, err := Prepare(directory, browserStatus(extension()))
	if err != nil || initial.Commit() != nil {
		t.Fatal(err)
	}

	updated := extension()
	updated.Version = "2.0"
	changes, versionOnly, err := Prepare(directory, browserStatus(updated))
	if err != nil || len(changes) != 0 {
		t.Fatalf("routine version update created a security change: %#v %v", changes, err)
	}
	if err := versionOnly.Commit(); err != nil {
		t.Fatal(err)
	}

	updated.SiteAccess = "all-sites"
	updated.SensitivePermissions = append(updated.SensitivePermissions, "cookies")
	changes, _, err = Prepare(directory, browserStatus(updated))
	if err != nil || len(changes) != 1 {
		t.Fatalf("expected one permission expansion: %#v %v", changes, err)
	}
	change := changes[0]
	if change.Kind != "permissions-expanded" || change.SiteAccess != "all-sites" || len(change.AddedPermissions) != 1 || change.AddedPermissions[0] != "cookies" || len(change.ID) != 24 {
		t.Fatalf("unexpected bounded change: %#v", change)
	}
}

func TestNewExtensionAndReEnablementAreDetected(t *testing.T) {
	directory := t.TempDir()
	empty := &model.BrowserSecurityStatus{Coverage: "observed", Browsers: []model.BrowserInstallation{{ID: "firefox", Name: "Mozilla Firefox", ProfileCount: 1, Extensions: []model.BrowserExtension{}}}}
	_, update, err := Prepare(directory, empty)
	if err != nil || update.Commit() != nil {
		t.Fatal(err)
	}
	item := extension()
	item.State = "disabled"
	status := &model.BrowserSecurityStatus{Coverage: "observed", Browsers: []model.BrowserInstallation{{ID: "firefox", Name: "Mozilla Firefox", ProfileCount: 1, Extensions: []model.BrowserExtension{item}}}}
	changes, update, err := Prepare(directory, status)
	if err != nil || len(changes) != 1 || changes[0].Kind != "installed" {
		t.Fatalf("new extension was not detected: %#v %v", changes, err)
	}
	if err := update.Commit(); err != nil {
		t.Fatal(err)
	}
	item.State = "active"
	changes, _, err = Prepare(directory, &model.BrowserSecurityStatus{Coverage: "observed", Browsers: []model.BrowserInstallation{{ID: "firefox", Name: "Mozilla Firefox", ProfileCount: 1, Extensions: []model.BrowserExtension{item}}}})
	if err != nil || len(changes) != 1 || changes[0].Kind != "enabled" {
		t.Fatalf("re-enabled extension was not detected: %#v %v", changes, err)
	}
}

func TestBaselineExcludesVersionsProfilesURLsAndCookieValues(t *testing.T) {
	directory := t.TempDir()
	item := extension()
	item.Version = "private-version-marker"
	_, update, err := Prepare(directory, browserStatus(item))
	if err != nil || update.Commit() != nil {
		t.Fatal(err)
	}
	contents, err := os.ReadFile(filepath.Join(directory, baselineFileName))
	if err != nil {
		t.Fatal(err)
	}
	if ContainsForbiddenBrowserMaterial(contents, "private-version-marker", "profilecount", "https://private.example", "session-cookie-value") {
		t.Fatalf("baseline retained forbidden browser material: %s", contents)
	}
	var decoded baseline
	if err := json.Unmarshal(contents, &decoded); err != nil || len(decoded.Extensions) != 1 {
		t.Fatalf("baseline did not remain valid: %#v %v", decoded, err)
	}
}

func TestInvalidBaselineRebaselinesWithoutInventingChanges(t *testing.T) {
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, baselineFileName), []byte(`{"version":1,"extensions":[],"cookie":"secret"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	changes, update, err := Prepare(directory, browserStatus(extension()))
	if !errors.Is(err, ErrInvalidBaseline) || len(changes) != 0 || update == nil {
		t.Fatalf("invalid baseline handling was unsafe: %#v %#v %v", changes, update, err)
	}
}

func TestBaselineRejectsUnknownBrowserAndPermissionFacts(t *testing.T) {
	for _, value := range []string{
		`{"version":1,"extensions":[{"browserId":"unknown","fingerprint":"0123456789abcdef01234567","name":"Extension","state":"active","siteAccess":"none-declared","optionalSiteAccess":"none-declared","sensitivePermissions":[],"optionalSensitivePermissions":[]}]}`,
		`{"version":1,"extensions":[{"browserId":"chrome","fingerprint":"0123456789abcdef01234567","name":"Extension","state":"active","siteAccess":"none-declared","optionalSiteAccess":"none-declared","sensitivePermissions":["cookie-value"],"optionalSensitivePermissions":[]}]}`,
	} {
		directory := t.TempDir()
		if err := os.WriteFile(filepath.Join(directory, baselineFileName), []byte(value), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, _, err := Prepare(directory, browserStatus(extension())); !errors.Is(err, ErrInvalidBaseline) {
			t.Fatalf("invalid baseline fact was accepted: %v", err)
		}
	}
}
