// Package sessionwatch compares privacy-reduced browser extension facts on the
// endpoint. The baseline never leaves the endpoint, and it deliberately has no
// representation for raw extension IDs, URL patterns, cookies, tokens, browser
// history, profile names, or browser-storage contents.
package sessionwatch

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/AdamWentworth/haven/internal/model"
)

const (
	baselineVersion      = 1
	maximumBaselineBytes = 1 << 20
	baselineFileName     = "browser-extension-baseline.json"
)

var ErrInvalidBaseline = errors.New("browser extension baseline is invalid")

type baseline struct {
	Version    int                 `json:"version"`
	Extensions []baselineExtension `json:"extensions"`
}

type baselineExtension struct {
	BrowserID                    string   `json:"browserId"`
	Fingerprint                  string   `json:"fingerprint"`
	Name                         string   `json:"name"`
	State                        string   `json:"state"`
	SiteAccess                   string   `json:"siteAccess"`
	OptionalSiteAccess           string   `json:"optionalSiteAccess"`
	SensitivePermissions         []string `json:"sensitivePermissions"`
	OptionalSensitivePermissions []string `json:"optionalSensitivePermissions"`
}

// Update is committed only after the hub has accepted the corresponding
// observation. Failed deliveries therefore cannot swallow a local change.
type Update struct {
	path     string
	contents []byte
}

func Prepare(directory string, status *model.BrowserSecurityStatus) ([]model.BrowserExtensionChange, *Update, error) {
	if status == nil || status.Coverage == "unavailable" {
		return nil, nil, nil
	}
	current := project(status)
	contents, err := json.MarshalIndent(current, "", "  ")
	if err != nil {
		return nil, nil, fmt.Errorf("encode browser extension baseline: %w", err)
	}
	update := &Update{path: filepath.Join(directory, baselineFileName), contents: contents}
	previous, found, err := load(update.path)
	if err != nil {
		return nil, update, err
	}
	if !found {
		return nil, update, nil
	}
	return compare(previous, current), update, nil
}

func (update *Update) Commit() error {
	if update == nil || update.path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(update.path), 0o700); err != nil {
		return fmt.Errorf("create browser baseline directory: %w", err)
	}
	temporary, err := os.CreateTemp(filepath.Dir(update.path), ".browser-baseline-*.tmp")
	if err != nil {
		return fmt.Errorf("create browser baseline: %w", err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("protect browser baseline: %w", err)
	}
	if _, err := temporary.Write(update.contents); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("write browser baseline: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("sync browser baseline: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close browser baseline: %w", err)
	}
	if err := os.Rename(temporaryPath, update.path); err != nil {
		return fmt.Errorf("replace browser baseline: %w", err)
	}
	return nil
}

func project(status *model.BrowserSecurityStatus) baseline {
	result := baseline{Version: baselineVersion, Extensions: []baselineExtension{}}
	for _, browser := range status.Browsers {
		for _, extension := range browser.Extensions {
			result.Extensions = append(result.Extensions, baselineExtension{
				BrowserID: browser.ID, Fingerprint: extension.Fingerprint, Name: extension.Name,
				State: extension.State, SiteAccess: extension.SiteAccess, OptionalSiteAccess: extension.OptionalSiteAccess,
				SensitivePermissions:         normalizedPermissions(extension.SensitivePermissions),
				OptionalSensitivePermissions: normalizedPermissions(extension.OptionalSensitivePermissions),
			})
		}
	}
	sort.Slice(result.Extensions, func(left, right int) bool {
		return baselineKey(result.Extensions[left]) < baselineKey(result.Extensions[right])
	})
	return result
}

func load(path string) (baseline, bool, error) {
	file, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return baseline{}, false, nil
	}
	if err != nil {
		return baseline{}, false, fmt.Errorf("read browser extension baseline: %w", err)
	}
	defer file.Close()
	decoder := json.NewDecoder(io.LimitReader(file, maximumBaselineBytes+1))
	decoder.DisallowUnknownFields()
	var value baseline
	if err := decoder.Decode(&value); err != nil {
		return baseline{}, false, ErrInvalidBaseline
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return baseline{}, false, ErrInvalidBaseline
	}
	if !validBaseline(value) {
		return baseline{}, false, ErrInvalidBaseline
	}
	return value, true, nil
}

func validBaseline(value baseline) bool {
	if value.Version != baselineVersion || len(value.Extensions) > 256 {
		return false
	}
	browsers := map[string]*model.BrowserInstallation{}
	seen := map[string]struct{}{}
	for _, extension := range value.Extensions {
		key := baselineKey(extension)
		if _, duplicate := seen[key]; duplicate {
			return false
		}
		seen[key] = struct{}{}
		browser, exists := browsers[extension.BrowserID]
		if !exists {
			name, known := baselineBrowserName(extension.BrowserID)
			if !known {
				return false
			}
			browser = &model.BrowserInstallation{ID: extension.BrowserID, Name: name, ProfileCount: 1, Extensions: []model.BrowserExtension{}}
			browsers[extension.BrowserID] = browser
		}
		browser.Extensions = append(browser.Extensions, model.BrowserExtension{
			Fingerprint: extension.Fingerprint, Name: extension.Name, State: extension.State, ProfileCount: 1,
			SiteAccess: extension.SiteAccess, OptionalSiteAccess: extension.OptionalSiteAccess,
			SensitivePermissions: extension.SensitivePermissions, OptionalSensitivePermissions: extension.OptionalSensitivePermissions,
		})
	}
	status := model.BrowserSecurityStatus{Coverage: "observed", Browsers: make([]model.BrowserInstallation, 0, len(browsers)), Protections: []model.BrowserProtectionStatus{}}
	for _, browser := range browsers {
		status.Browsers = append(status.Browsers, *browser)
	}
	return model.ValidateBrowserSecurity(&status)
}

func baselineBrowserName(id string) (string, bool) {
	names := map[string]string{
		"brave": "Brave", "chrome": "Google Chrome", "chromium": "Chromium", "chromium-snap": "Chromium (Snap)",
		"edge": "Microsoft Edge", "firefox": "Mozilla Firefox", "firefox-snap": "Mozilla Firefox (Snap)",
	}
	name, found := names[id]
	return name, found
}

func compare(previous, current baseline) []model.BrowserExtensionChange {
	before := make(map[string]baselineExtension, len(previous.Extensions))
	for _, extension := range previous.Extensions {
		before[baselineKey(extension)] = extension
	}
	changes := []model.BrowserExtensionChange{}
	for _, extension := range current.Extensions {
		prior, existed := before[baselineKey(extension)]
		kind := ""
		addedPermissions := []string{}
		if !existed {
			kind = "installed"
			addedPermissions = combinedPermissions(extension)
		} else {
			addedPermissions = permissionDifference(combinedPermissions(extension), combinedPermissions(prior))
			if siteAccessRank(effectiveSiteAccess(extension)) > siteAccessRank(effectiveSiteAccess(prior)) || len(addedPermissions) > 0 {
				kind = "permissions-expanded"
			} else if prior.State == "disabled" && extension.State != "disabled" {
				kind = "enabled"
			}
		}
		if kind == "" {
			continue
		}
		change := model.BrowserExtensionChange{
			BrowserID: extension.BrowserID, Fingerprint: extension.Fingerprint,
			ExtensionName: extension.Name, Kind: kind,
			SiteAccess: effectiveSiteAccess(extension), AddedPermissions: addedPermissions,
		}
		change.ID = changeFingerprint(change)
		changes = append(changes, change)
		if len(changes) == 32 {
			break
		}
	}
	sort.Slice(changes, func(left, right int) bool { return changes[left].ID < changes[right].ID })
	return changes
}

func effectiveSiteAccess(extension baselineExtension) string {
	if siteAccessRank(extension.OptionalSiteAccess) > siteAccessRank(extension.SiteAccess) {
		return extension.OptionalSiteAccess
	}
	return extension.SiteAccess
}

func siteAccessRank(value string) int {
	switch value {
	case "none-declared":
		return 0
	case "specific-sites":
		return 1
	case "all-sites":
		return 2
	default:
		return -1
	}
}

func combinedPermissions(extension baselineExtension) []string {
	return normalizedPermissions(append(append([]string{}, extension.SensitivePermissions...), extension.OptionalSensitivePermissions...))
}

func normalizedPermissions(values []string) []string {
	seen := map[string]struct{}{}
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.ToLower(strings.TrimSpace(value))
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func permissionDifference(current, previous []string) []string {
	known := map[string]struct{}{}
	for _, value := range previous {
		known[value] = struct{}{}
	}
	result := []string{}
	for _, value := range current {
		if _, exists := known[value]; !exists {
			result = append(result, value)
		}
	}
	return result
}

func baselineKey(extension baselineExtension) string {
	return extension.BrowserID + ":" + extension.Fingerprint
}

func changeFingerprint(change model.BrowserExtensionChange) string {
	parts := []string{change.BrowserID, change.Fingerprint, change.Kind, change.SiteAccess, strings.Join(change.AddedPermissions, ",")}
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(sum[:12])
}

// ContainsForbiddenBrowserMaterial is used by tests to prove that serialized
// baselines cannot contain cookie values, URL patterns, or raw browser IDs.
func ContainsForbiddenBrowserMaterial(value []byte, forbidden ...string) bool {
	lower := bytes.ToLower(value)
	for _, item := range forbidden {
		if bytes.Contains(lower, bytes.ToLower([]byte(item))) {
			return true
		}
	}
	return false
}
