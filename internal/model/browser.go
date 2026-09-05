package model

import (
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

var browserFingerprintPattern = regexp.MustCompile(`^[0-9a-f]{24}$`)

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
	if len(status.Browsers) > 8 || len(status.Protections) > 8 {
		return false
	}
	seenBrowsers := map[string]struct{}{}
	totalExtensions := 0
	for _, browser := range status.Browsers {
		canonicalName, allowed := allowedBrowserIdentities[browser.ID]
		if !allowed || browser.Name != canonicalName || !safeBrowserText(browser.Name, 100, false) || !safeBrowserText(browser.Version, 40, true) || browser.ProfileCount < 0 || browser.ProfileCount > 32 || len(browser.Extensions) > 100 {
			return false
		}
		if _, exists := seenBrowsers[browser.ID]; exists {
			return false
		}
		seenBrowsers[browser.ID] = struct{}{}
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
	if status.Coverage == "unavailable" && len(status.Browsers) != 0 {
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
		if protection.State != "enabled" && protection.State != "audit" && protection.State != "disabled" && protection.State != "unknown" {
			return false
		}
		if _, exists := seenProtections[protection.ID]; exists {
			return false
		}
		seenProtections[protection.ID] = struct{}{}
	}
	return true
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
