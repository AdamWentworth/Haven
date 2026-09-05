package model

import (
	"fmt"
	"testing"
)

func TestValidateBrowserSecurityAcceptsPrivacyReducedInventory(t *testing.T) {
	status := &BrowserSecurityStatus{
		Coverage: "observed",
		Browsers: []BrowserInstallation{{
			ID: "chrome", Name: "Google Chrome", Version: "140.0.1", ProfileCount: 1,
			Extensions: []BrowserExtension{{Fingerprint: "0123456789abcdef01234567", Name: "Password Helper", Version: "1.2.3", State: "installed", ProfileCount: 1, SiteAccess: "all-sites", OptionalSiteAccess: "none-declared", SensitivePermissions: []string{"cookies"}, OptionalSensitivePermissions: []string{}}},
		}},
		Protections: []BrowserProtectionStatus{{ID: "defender-pua", Name: "Potentially unwanted app protection", State: "enabled", Source: "Microsoft Defender preferences"}},
	}
	if !ValidateBrowserSecurity(status) {
		t.Fatal("valid bounded browser inventory was rejected")
	}
}

func TestValidateBrowserSecurityRejectsIdentifiersAndUnboundedFacts(t *testing.T) {
	base := BrowserSecurityStatus{Coverage: "observed", Browsers: []BrowserInstallation{{ID: "chrome", Name: "Google Chrome", ProfileCount: 1, Extensions: []BrowserExtension{{Fingerprint: "0123456789abcdef01234567", Name: "Extension", State: "installed", ProfileCount: 1, SiteAccess: "none-declared", OptionalSiteAccess: "none-declared"}}}}}
	if !ValidateBrowserSecurity(&base) {
		t.Fatal("test fixture is invalid")
	}
	base.Browsers[0].Extensions[0].Fingerprint = "raw-extension-id@example"
	if ValidateBrowserSecurity(&base) {
		t.Fatal("raw extension identifier was accepted")
	}
	base.Browsers[0].Extensions[0].Fingerprint = "0123456789abcdef01234567"
	base.Browsers[0].Extensions[0].SiteAccess = "https://private.example/*"
	if ValidateBrowserSecurity(&base) {
		t.Fatal("raw host match pattern was accepted")
	}
	base.Browsers[0].Extensions[0].SiteAccess = "none-declared"
	base.Browsers[0].Extensions[0].SensitivePermissions = []string{"https://private.example/*"}
	if ValidateBrowserSecurity(&base) {
		t.Fatal("unrecognized permission text was accepted")
	}
}

func TestValidateBrowserSecurityRejectsEndpointDefinedPresentation(t *testing.T) {
	status := BrowserSecurityStatus{Coverage: "observed", Browsers: []BrowserInstallation{{ID: "chrome", Name: "Not Chrome", ProfileCount: 0, Extensions: []BrowserExtension{}}}}
	if ValidateBrowserSecurity(&status) {
		t.Fatal("an endpoint-defined browser name was accepted")
	}
	status.Browsers[0].Name = "Google Chrome"
	status.Protections = []BrowserProtectionStatus{{ID: "defender-network", Name: "Endpoint supplied claim", State: "enabled", Source: "Microsoft Defender preferences"}}
	if ValidateBrowserSecurity(&status) {
		t.Fatal("an endpoint-defined protection name was accepted")
	}
	status.Protections = nil
	status.Browsers[0].Extensions = []BrowserExtension{{Fingerprint: "0123456789abcdef01234567", Name: "Unsafe\nname", State: "installed", ProfileCount: 1, SiteAccess: "none-declared", OptionalSiteAccess: "none-declared"}}
	if ValidateBrowserSecurity(&status) {
		t.Fatal("control characters in extension text were accepted")
	}
}

func TestValidateBrowserSecurityRejectsAmbiguousUnavailableInventory(t *testing.T) {
	status := BrowserSecurityStatus{Coverage: "unavailable", Browsers: []BrowserInstallation{{ID: "chrome", Name: "Google Chrome", ProfileCount: 0}}}
	if ValidateBrowserSecurity(&status) {
		t.Fatal("unavailable coverage with asserted browser facts was accepted")
	}
}

func TestValidateBrowserSecurityBoundsTotalExtensionInventory(t *testing.T) {
	status := BrowserSecurityStatus{Coverage: "observed"}
	identities := []struct{ id, name string }{{"chrome", "Google Chrome"}, {"edge", "Microsoft Edge"}, {"firefox", "Mozilla Firefox"}}
	sequence := 0
	for _, identity := range identities {
		browser := BrowserInstallation{ID: identity.id, Name: identity.name, ProfileCount: 1}
		for index := 0; index < 86; index++ {
			sequence++
			browser.Extensions = append(browser.Extensions, BrowserExtension{Fingerprint: fmt.Sprintf("%024x", sequence), Name: "Extension", State: "installed", ProfileCount: 1, SiteAccess: "none-declared", OptionalSiteAccess: "none-declared"})
		}
		status.Browsers = append(status.Browsers, browser)
	}
	if ValidateBrowserSecurity(&status) {
		t.Fatal("an inventory above the global extension bound was accepted")
	}
}

func TestValidateBrowserSecurityAcceptsBoundedSessionDefenseEvidence(t *testing.T) {
	eventCount := 2
	change := BrowserExtensionChange{BrowserID: "chrome", Fingerprint: "0123456789abcdef01234567", ExtensionName: "Password Helper", Kind: "permissions-expanded", SiteAccess: "all-sites", AddedPermissions: []string{"cookies"}}
	change.ID = expectedBrowserChangeID(change)
	status := &BrowserSecurityStatus{
		Coverage: "observed",
		Browsers: []BrowserInstallation{{
			ID: "chrome", Name: "Google Chrome", ProfileCount: 1,
			Extensions: []BrowserExtension{{Fingerprint: "0123456789abcdef01234567", Name: "Password Helper", State: "active", ProfileCount: 1, SiteAccess: "specific-sites", OptionalSiteAccess: "all-sites", SensitivePermissions: []string{"cookies"}}},
		}},
		Protections: []BrowserProtectionStatus{
			{ID: "chrome-app-bound-encryption", Name: "Chrome App-Bound Encryption policy", State: "default", Source: "Chrome policy"},
			{ID: "chrome-device-bound-sessions", Name: "Chrome device-bound Google sessions", State: "enabled", Source: "Chrome policy"},
			{ID: "chrome-cookie-verification-events", Name: "Chrome cookie-protection verification", State: "attention", Source: "Windows Application event log", EventCount: &eventCount},
		},
		Changes: []BrowserExtensionChange{change},
	}
	if !ValidateBrowserSecurity(status) {
		t.Fatal("valid session-defense evidence was rejected")
	}
}

func TestValidateBrowserSecurityRejectsInventedChangeEvidence(t *testing.T) {
	change := BrowserExtensionChange{BrowserID: "chrome", Fingerprint: "0123456789abcdef01234567", ExtensionName: "Password Helper", Kind: "permissions-expanded", SiteAccess: "all-sites", AddedPermissions: []string{"cookies"}}
	change.ID = expectedBrowserChangeID(change)
	status := BrowserSecurityStatus{
		Coverage: "observed",
		Browsers: []BrowserInstallation{{
			ID: "chrome", Name: "Google Chrome", ProfileCount: 1,
			Extensions: []BrowserExtension{{Fingerprint: "0123456789abcdef01234567", Name: "Password Helper", State: "active", ProfileCount: 1, SiteAccess: "specific-sites", OptionalSiteAccess: "none-declared", SensitivePermissions: []string{"history"}}},
		}},
		Changes: []BrowserExtensionChange{change},
	}
	if ValidateBrowserSecurity(&status) {
		t.Fatal("change evidence exceeding the matching current extension was accepted")
	}
}

func TestValidateBrowserSecurityRejectsInvalidCookieVerificationCounts(t *testing.T) {
	zero := 0
	status := BrowserSecurityStatus{Coverage: "observed", Protections: []BrowserProtectionStatus{{ID: "chrome-cookie-verification-events", Name: "Chrome cookie-protection verification", State: "attention", Source: "Windows Application event log", EventCount: &zero}}}
	if ValidateBrowserSecurity(&status) {
		t.Fatal("an attention state with zero events was accepted")
	}
	status.Protections[0].State = "clear"
	if !ValidateBrowserSecurity(&status) {
		t.Fatal("a clear state with zero events was rejected")
	}
	status.Protections[0].EventCount = nil
	if ValidateBrowserSecurity(&status) {
		t.Fatal("a clear state without bounded evidence was accepted")
	}
	status.Protections = []BrowserProtectionStatus{{ID: "chrome-app-bound-encryption", Name: "Chrome App-Bound Encryption policy", State: "clear", Source: "Chrome policy"}}
	if ValidateBrowserSecurity(&status) {
		t.Fatal("an event-only state was accepted for a Chrome policy")
	}
	status.Protections = []BrowserProtectionStatus{{ID: "defender-pua", Name: "Potentially unwanted app protection", State: "default", Source: "Microsoft Defender preferences"}}
	if ValidateBrowserSecurity(&status) {
		t.Fatal("a Chrome-policy state was accepted for Defender evidence")
	}
}
