package model

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

var browserFingerprintPattern = regexp.MustCompile(`^[0-9a-f]{24}$`)
var browserDomainPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$`)

var allowedBrowserIdentities = map[string]string{
	"brave":         "Brave",
	"chrome":        "Google Chrome",
	"chromium":      "Chromium",
	"chromium-snap": "Chromium (Snap)",
	"edge":          "Microsoft Edge",
	"firefox":       "Mozilla Firefox",
	"firefox-snap":  "Mozilla Firefox (Snap)",
}

var allowedBrowserProtections = map[string]struct {
	name    string
	sources map[string]struct{}
}{
	"defender-pua":     {name: "Potentially unwanted app protection", sources: map[string]struct{}{"Microsoft Defender preferences": {}}},
	"defender-network": {name: "Microsoft Defender Network Protection", sources: map[string]struct{}{"Microsoft Defender preferences": {}}},
	"windows-smartscreen": {name: "Microsoft Defender SmartScreen", sources: map[string]struct{}{
		"Windows policy": {}, "Windows shell configuration": {},
	}},
	"chrome-app-bound-encryption": {name: "Chrome App-Bound Encryption policy", sources: map[string]struct{}{
		"Chrome policy": {},
	}},
	"chrome-device-bound-sessions": {name: "Chrome device-bound Google sessions", sources: map[string]struct{}{
		"Chrome policy": {},
	}},
	"chrome-cookie-verification-events": {name: "Chrome cookie-protection verification", sources: map[string]struct{}{
		"Windows Application event log": {},
	}},
}

var allowedBrowserPermissions = map[string]struct{}{
	"bookmarks": {}, "browsingdata": {}, "clipboardread": {}, "cookies": {},
	"debugger": {}, "downloads": {}, "history": {}, "management": {},
	"nativemessaging": {}, "pagecapture": {}, "privacy": {}, "proxy": {},
	"scripting": {}, "sessions": {}, "tabs": {}, "topsites": {},
	"webauthenticationproxy": {}, "webnavigation": {}, "webrequest": {},
	"webrequestblocking": {},
}

// ValidateBrowserSecurity bounds all endpoint-asserted browser facts before
// they can enter hub persistence or presentation. It intentionally validates
// only the privacy-reduced schema; raw IDs and host match patterns have no
// representation in that schema.
func ValidateBrowserSecurity(status *BrowserSecurityStatus) bool {
	if status == nil {
		return true
	}
	if status.Coverage != "observed" && status.Coverage != "partial" && status.Coverage != "unavailable" {
		return false
	}
	if len(status.Browsers) > 8 || len(status.Protections) > 8 || len(status.Changes) > 32 {
		return false
	}
	seenBrowsers := map[string]struct{}{}
	totalExtensions := 0
	totalCookieSites := 0
	for _, browser := range status.Browsers {
		canonicalName, allowed := allowedBrowserIdentities[browser.ID]
		if !allowed || browser.Name != canonicalName || !safeBrowserText(browser.Name, 100, false) || !safeBrowserText(browser.Version, 40, true) || browser.ProfileCount < 0 || browser.ProfileCount > 32 || len(browser.Extensions) > 100 {
			return false
		}
		if _, exists := seenBrowsers[browser.ID]; exists {
			return false
		}
		seenBrowsers[browser.ID] = struct{}{}
		if len(browser.Profiles) > 32 || len(browser.Profiles) > browser.ProfileCount || (browser.ID != "chrome" && len(browser.Profiles) != 0) {
			return false
		}
		seenProfiles := map[string]struct{}{}
		for _, profile := range browser.Profiles {
			if !browserFingerprintPattern.MatchString(profile.Fingerprint) || !safeBrowserText(profile.Name, 100, false) || (profile.CookieStatus != "observed" && profile.CookieStatus != "partial" && profile.CookieStatus != "unavailable") || profile.CookieCount < 0 || profile.CookieCount > 100000 || len(profile.Sites) > 256 {
				return false
			}
			if _, exists := seenProfiles[profile.Fingerprint]; exists {
				return false
			}
			seenProfiles[profile.Fingerprint] = struct{}{}
			if profile.CookieStatus == "unavailable" && (profile.CookieCount != 0 || len(profile.Sites) != 0 || profile.Truncated) {
				return false
			}
			if profile.Truncated && profile.CookieStatus != "partial" {
				return false
			}
			totalCookieSites += len(profile.Sites)
			if totalCookieSites > 1024 {
				return false
			}
			seenSites := map[string]struct{}{}
			observedCookies := 0
			for _, site := range profile.Sites {
				if !validCookieDomain(site.Domain) || site.CookieCount < 1 || site.CookieCount > 10000 || site.SessionCookieCount < 0 || site.PersistentCookieCount < 0 || site.SessionCookieCount+site.PersistentCookieCount != site.CookieCount || site.SecureCookieCount < 0 || site.SecureCookieCount > site.CookieCount || site.HTTPOnlyCookieCount < 0 || site.HTTPOnlyCookieCount > site.CookieCount || !validBrowserTime(site.LastAccessedAt) || !validBrowserTime(site.LatestExpiryAt) {
					return false
				}
				if _, exists := seenSites[site.Domain]; exists {
					return false
				}
				seenSites[site.Domain] = struct{}{}
				observedCookies += site.CookieCount
			}
			if observedCookies > profile.CookieCount || (profile.CookieStatus == "observed" && observedCookies != profile.CookieCount) {
				return false
			}
		}
		totalExtensions += len(browser.Extensions)
		if totalExtensions > 256 {
			return false
		}
		seenExtensions := map[string]struct{}{}
		for _, extension := range browser.Extensions {
			if !browserFingerprintPattern.MatchString(extension.Fingerprint) || !safeBrowserText(extension.Name, 100, false) || !safeBrowserText(extension.Version, 40, true) || extension.ProfileCount < 1 || extension.ProfileCount > 32 {
				return false
			}
			if extension.State != "installed" && extension.State != "active" && extension.State != "disabled" {
				return false
			}
			if !validSiteAccess(extension.SiteAccess) || !validSiteAccess(extension.OptionalSiteAccess) || !validPermissionList(extension.SensitivePermissions) || !validPermissionList(extension.OptionalSensitivePermissions) {
				return false
			}
			if _, exists := seenExtensions[extension.Fingerprint]; exists {
				return false
			}
			seenExtensions[extension.Fingerprint] = struct{}{}
		}
	}
	if status.Coverage == "unavailable" && (len(status.Browsers) != 0 || len(status.Changes) != 0) {
		return false
	}
	seenProtections := map[string]struct{}{}
	for _, protection := range status.Protections {
		definition, allowed := allowedBrowserProtections[protection.ID]
		if !allowed || protection.Name != definition.name || !safeBrowserText(protection.Name, 100, false) {
			return false
		}
		if _, allowed := definition.sources[protection.Source]; !allowed {
			return false
		}
		if !validProtectionEvidence(protection) {
			return false
		}
		if _, exists := seenProtections[protection.ID]; exists {
			return false
		}
		seenProtections[protection.ID] = struct{}{}
	}
	seenChanges := map[string]struct{}{}
	for _, change := range status.Changes {
		if !browserFingerprintPattern.MatchString(change.ID) || !browserFingerprintPattern.MatchString(change.Fingerprint) || !safeBrowserText(change.ExtensionName, 100, false) || !validSiteAccess(change.SiteAccess) || !validPermissionList(change.AddedPermissions) || change.ID != expectedBrowserChangeID(change) {
			return false
		}
		if change.Kind != "installed" && change.Kind != "enabled" && change.Kind != "permissions-expanded" {
			return false
		}
		if (change.Kind == "enabled" && len(change.AddedPermissions) != 0) || (change.Kind == "permissions-expanded" && change.SiteAccess == "none-declared" && len(change.AddedPermissions) == 0) {
			return false
		}
		if _, allowed := allowedBrowserIdentities[change.BrowserID]; !allowed {
			return false
		}
		if _, duplicate := seenChanges[change.ID]; duplicate {
			return false
		}
		seenChanges[change.ID] = struct{}{}
		matched := false
		for _, browser := range status.Browsers {
			if browser.ID != change.BrowserID {
				continue
			}
			for _, extension := range browser.Extensions {
				if extension.Fingerprint == change.Fingerprint && extension.Name == change.ExtensionName {
					if change.SiteAccess != broaderSiteAccess(extension.SiteAccess, extension.OptionalSiteAccess) || !permissionSubset(change.AddedPermissions, extension.SensitivePermissions, extension.OptionalSensitivePermissions) {
						return false
					}
					matched = true
					break
				}
			}
		}
		if !matched {
			return false
		}
	}
	return true
}

func validCookieDomain(value string) bool {
	return value == strings.ToLower(value) && browserDomainPattern.MatchString(value) && !strings.Contains(value, "..")
}

func validBrowserTime(value *time.Time) bool {
	if value == nil {
		return true
	}
	utc := value.UTC()
	return !utc.Before(time.Date(2000, time.January, 1, 0, 0, 0, 0, time.UTC)) && utc.Before(time.Date(2101, time.January, 1, 0, 0, 0, 0, time.UTC))
}

func validProtectionEvidence(protection BrowserProtectionStatus) bool {
	if protection.ID == "chrome-cookie-verification-events" {
		if protection.State == "unknown" {
			return protection.EventCount == nil
		}
		if protection.EventCount == nil || *protection.EventCount < 0 || *protection.EventCount > 50 {
			return false
		}
		return (protection.State == "clear" && *protection.EventCount == 0) || (protection.State == "attention" && *protection.EventCount > 0)
	}
	if protection.EventCount != nil {
		return false
	}
	if protection.ID == "chrome-app-bound-encryption" || protection.ID == "chrome-device-bound-sessions" {
		return protection.State == "enabled" || protection.State == "disabled" || protection.State == "unknown" || protection.State == "default"
	}
	return protection.State == "enabled" || protection.State == "audit" || protection.State == "disabled" || protection.State == "unknown"
}

func expectedBrowserChangeID(change BrowserExtensionChange) string {
	parts := []string{change.BrowserID, change.Fingerprint, change.Kind, change.SiteAccess, strings.Join(change.AddedPermissions, ",")}
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(sum[:12])
}

func safeBrowserText(value string, maximum int, allowEmpty bool) bool {
	if !utf8.ValidString(value) || len(value) > maximum || (!allowEmpty && len(value) == 0) {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func validSiteAccess(value string) bool {
	return value == "none-declared" || value == "specific-sites" || value == "all-sites"
}

func validPermissionList(values []string) bool {
	if len(values) > 24 {
		return false
	}
	seen := map[string]struct{}{}
	for _, value := range values {
		if len(value) < 1 || len(value) > 40 {
			return false
		}
		normalized := strings.ToLower(value)
		if _, allowed := allowedBrowserPermissions[normalized]; !allowed {
			return false
		}
		if _, exists := seen[normalized]; exists {
			return false
		}
		seen[normalized] = struct{}{}
	}
	return true
}

func broaderSiteAccess(left, right string) string {
	rank := func(value string) int {
		switch value {
		case "specific-sites":
			return 1
		case "all-sites":
			return 2
		default:
			return 0
		}
	}
	if rank(right) > rank(left) {
		return right
	}
	return left
}

func permissionSubset(candidate []string, required []string, optional []string) bool {
	available := map[string]struct{}{}
	for _, value := range append(append([]string{}, required...), optional...) {
		available[strings.ToLower(value)] = struct{}{}
	}
	for _, value := range candidate {
		if _, exists := available[strings.ToLower(value)]; !exists {
			return false
		}
	}
	return true
}
