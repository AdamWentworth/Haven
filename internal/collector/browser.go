package collector

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"github.com/AdamWentworth/haven/internal/model"
)

const (
	maximumBrowserProfiles        = 32
	maximumBrowserExtensions      = 100
	maximumBrowserExtensionsTotal = 256
	maximumManifestBytes          = 512 << 10
	maximumFirefoxStateBytes      = 4 << 20
)

type browserRoot struct {
	id   string
	name string
	kind string
	path string
}

type browserExtensionManifest struct {
	Name                    string   `json:"name"`
	Version                 string   `json:"version"`
	DefaultLocale           string   `json:"default_locale"`
	Permissions             []string `json:"permissions"`
	OptionalPermissions     []string `json:"optional_permissions"`
	HostPermissions         []string `json:"host_permissions"`
	OptionalHostPermissions []string `json:"optional_host_permissions"`
	ContentScripts          []struct {
		Matches []string `json:"matches"`
	} `json:"content_scripts"`
}

type firefoxExtensionState struct {
	Addons []struct {
		ID            string `json:"id"`
		Type          string `json:"type"`
		Active        bool   `json:"active"`
		Hidden        bool   `json:"hidden"`
		Version       string `json:"version"`
		DefaultLocale struct {
			Name string `json:"name"`
		} `json:"defaultLocale"`
		UserPermissions struct {
			Permissions []string `json:"permissions"`
			Origins     []string `json:"origins"`
		} `json:"userPermissions"`
		OptionalPermissions struct {
			Permissions []string `json:"permissions"`
			Origins     []string `json:"origins"`
		} `json:"optionalPermissions"`
	} `json:"addons"`
}

type extensionAccumulator struct {
	extension model.BrowserExtension
	profiles  map[string]struct{}
}

var sensitiveBrowserPermissions = map[string]struct{}{
	"bookmarks": {}, "browsingdata": {}, "clipboardread": {}, "cookies": {},
	"debugger": {}, "downloads": {}, "history": {}, "management": {},
	"nativemessaging": {}, "pagecapture": {}, "privacy": {}, "proxy": {},
	"scripting": {}, "sessions": {}, "tabs": {}, "topsites": {},
	"webauthenticationproxy": {}, "webnavigation": {}, "webrequest": {},
	"webrequestblocking": {},
}

func collectBrowserSecurity(platform string) (*model.BrowserSecurityStatus, []model.CollectorNotice) {
	roots, rootsAvailable := defaultBrowserRoots(platform)
	status := &model.BrowserSecurityStatus{Coverage: "observed", Browsers: []model.BrowserInstallation{}, Protections: []model.BrowserProtectionStatus{}}
	if !rootsAvailable {
		status.Coverage = "unavailable"
		return status, []model.CollectorNotice{{Source: "Browser inventory", Severity: "information", Message: "Supported browser profiles could not be located for this user session."}}
	}

	partial := false
	for _, root := range roots {
		browser, found, incomplete := scanBrowserRoot(root)
		partial = partial || incomplete
		if found {
			status.Browsers = append(status.Browsers, browser)
		}
	}
	sort.Slice(status.Browsers, func(left, right int) bool { return status.Browsers[left].Name < status.Browsers[right].Name })
	remainingExtensions := maximumBrowserExtensionsTotal
	for index := range status.Browsers {
		if len(status.Browsers[index].Extensions) > remainingExtensions {
			status.Browsers[index].Extensions = status.Browsers[index].Extensions[:remainingExtensions]
			partial = true
		}
		remainingExtensions -= len(status.Browsers[index].Extensions)
	}
	if partial {
		status.Coverage = "partial"
		return status, []model.CollectorNotice{{Source: "Browser inventory", Severity: "information", Message: "Some supported browser metadata could not be read; HAVEN retained only the bounded facts it could verify."}}
	}
	return status, nil
}

func attachBrowserSecurity(snapshot *model.SecuritySnapshot, platform string) {
	inventory, notices := collectBrowserSecurity(platform)
	if snapshot.BrowserSecurity != nil {
		inventory.Protections = append([]model.BrowserProtectionStatus(nil), snapshot.BrowserSecurity.Protections...)
	}
	if platform == "windows" && !containsBrowser(inventory.Browsers, "chrome") {
		filtered := make([]model.BrowserProtectionStatus, 0, len(inventory.Protections))
		for _, protection := range inventory.Protections {
			if strings.HasPrefix(protection.ID, "chrome-") {
				continue
			}
			filtered = append(filtered, protection)
		}
		inventory.Protections = filtered
	}
	snapshot.BrowserSecurity = inventory
	snapshot.Notices = append(snapshot.Notices, notices...)
}

func containsBrowser(browsers []model.BrowserInstallation, id string) bool {
	for _, browser := range browsers {
		if browser.ID == id {
			return true
		}
	}
	return false
}

func defaultBrowserRoots(platform string) ([]browserRoot, bool) {
	switch platform {
	case "windows":
		local := strings.TrimSpace(os.Getenv("LOCALAPPDATA"))
		roaming := strings.TrimSpace(os.Getenv("APPDATA"))
		roots := []browserRoot{}
		if local != "" {
			roots = append(roots,
				browserRoot{id: "chrome", name: "Google Chrome", kind: "chromium", path: filepath.Join(local, "Google", "Chrome", "User Data")},
				browserRoot{id: "edge", name: "Microsoft Edge", kind: "chromium", path: filepath.Join(local, "Microsoft", "Edge", "User Data")},
				browserRoot{id: "brave", name: "Brave", kind: "chromium", path: filepath.Join(local, "BraveSoftware", "Brave-Browser", "User Data")},
				browserRoot{id: "chromium", name: "Chromium", kind: "chromium", path: filepath.Join(local, "Chromium", "User Data")},
			)
		}
		if roaming != "" {
			roots = append(roots, browserRoot{id: "firefox", name: "Mozilla Firefox", kind: "firefox", path: filepath.Join(roaming, "Mozilla", "Firefox", "Profiles")})
		}
		return roots, local != "" || roaming != ""
	case "linux":
		home, err := os.UserHomeDir()
		if err != nil || strings.TrimSpace(home) == "" {
			return nil, false
		}
		return []browserRoot{
			{id: "chrome", name: "Google Chrome", kind: "chromium", path: filepath.Join(home, ".config", "google-chrome")},
			{id: "edge", name: "Microsoft Edge", kind: "chromium", path: filepath.Join(home, ".config", "microsoft-edge")},
			{id: "brave", name: "Brave", kind: "chromium", path: filepath.Join(home, ".config", "BraveSoftware", "Brave-Browser")},
			{id: "chromium", name: "Chromium", kind: "chromium", path: filepath.Join(home, ".config", "chromium")},
			{id: "chromium-snap", name: "Chromium (Snap)", kind: "chromium", path: filepath.Join(home, "snap", "chromium", "common", "chromium")},
			{id: "firefox", name: "Mozilla Firefox", kind: "firefox", path: filepath.Join(home, ".mozilla", "firefox")},
			{id: "firefox-snap", name: "Mozilla Firefox (Snap)", kind: "firefox", path: filepath.Join(home, "snap", "firefox", "common", ".mozilla", "firefox")},
		}, true
	default:
		return nil, false
	}
}

func scanBrowserRoot(root browserRoot) (model.BrowserInstallation, bool, bool) {
	if _, err := os.Stat(root.path); errors.Is(err, os.ErrNotExist) {
		return model.BrowserInstallation{}, false, false
	} else if err != nil {
		return model.BrowserInstallation{}, false, true
	}
	browser := model.BrowserInstallation{ID: root.id, Name: root.name, Extensions: []model.BrowserExtension{}}
	if root.kind == "firefox" {
		return scanFirefoxRoot(root, browser)
	}
	return scanChromiumRoot(root, browser)
}

func scanChromiumRoot(root browserRoot, browser model.BrowserInstallation) (model.BrowserInstallation, bool, bool) {
	if version, err := readBoundedText(filepath.Join(root.path, "Last Version"), 128); err == nil {
		browser.Version = boundedText(version, 40)
	}
	entries, truncated, err := readDirectoryBounded(root.path, maximumBrowserProfiles*4)
	if err != nil {
		return browser, true, true
	}
	accumulators := map[string]*extensionAccumulator{}
	partial := truncated
	profiles := 0
	for _, entry := range entries {
		if !entry.IsDir() || !isChromiumUserProfile(entry.Name()) || profiles >= maximumBrowserProfiles {
			continue
		}
		profilePath := filepath.Join(root.path, entry.Name())
		if !exists(filepath.Join(profilePath, "Preferences")) && !exists(filepath.Join(profilePath, "Extensions")) {
			continue
		}
		profiles++
		if incomplete := scanChromiumExtensions(root.id, entry.Name(), filepath.Join(profilePath, "Extensions"), accumulators); incomplete {
			partial = true
		}
	}
	browser.ProfileCount = profiles
	browser.Extensions = accumulatedExtensions(accumulators)
	if len(browser.Extensions) > maximumBrowserExtensions {
		browser.Extensions = browser.Extensions[:maximumBrowserExtensions]
		partial = true
	}
	return browser, true, partial
}

func scanChromiumExtensions(browserID, profileKey, directory string, accumulators map[string]*extensionAccumulator) bool {
	entries, truncated, err := readDirectoryBounded(directory, maximumBrowserExtensions)
	if errors.Is(err, os.ErrNotExist) {
		return false
	}
	if err != nil {
		return true
	}
	partial := truncated
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		manifest, manifestPath, err := latestChromiumManifest(filepath.Join(directory, entry.Name()))
		if err != nil {
			partial = true
			continue
		}
		name := localizedManifestName(manifestPath, manifest)
		if name == "" {
			name = "Unnamed extension"
		}
		extension := model.BrowserExtension{
			Fingerprint:                  extensionFingerprint(browserID, entry.Name()),
			Name:                         name,
			Version:                      boundedText(manifest.Version, 40),
			State:                        "installed",
			SiteAccess:                   siteAccess(append(append([]string{}, hostPatterns(manifest.Permissions)...), append(manifest.HostPermissions, contentScriptMatches(manifest)...)...)),
			OptionalSiteAccess:           siteAccess(append(hostPatterns(manifest.OptionalPermissions), manifest.OptionalHostPermissions...)),
			SensitivePermissions:         sensitivePermissions(manifest.Permissions),
			OptionalSensitivePermissions: sensitivePermissions(manifest.OptionalPermissions),
		}
		accumulateExtension(accumulators, profileKey, extension)
	}
	return partial
}

func latestChromiumManifest(extensionDirectory string) (browserExtensionManifest, string, error) {
	versions, truncated, err := readDirectoryBounded(extensionDirectory, 32)
	if err != nil {
		return browserExtensionManifest{}, "", err
	}
	if truncated {
		return browserExtensionManifest{}, "", errors.New("extension has too many version directories")
	}
	sort.SliceStable(versions, func(left, right int) bool {
		return compareBrowserVersions(versions[left].Name(), versions[right].Name()) > 0
	})
	for _, version := range versions {
		if !version.IsDir() {
			continue
		}
		path := filepath.Join(extensionDirectory, version.Name(), "manifest.json")
		var manifest browserExtensionManifest
		if err := readBoundedJSON(path, maximumManifestBytes, &manifest); err == nil {
			return manifest, path, nil
		}
	}
	return browserExtensionManifest{}, "", errors.New("no readable extension manifest")
}

func localizedManifestName(manifestPath string, manifest browserExtensionManifest) string {
	name := boundedText(manifest.Name, 100)
	if !strings.HasPrefix(name, "__MSG_") || !strings.HasSuffix(name, "__") {
		return name
	}
	locale := boundedToken(manifest.DefaultLocale, 24)
	messageKey := strings.TrimSuffix(strings.TrimPrefix(name, "__MSG_"), "__")
	messageKey = boundedToken(messageKey, 80)
	if locale == "" || messageKey == "" {
		return ""
	}
	messagesPath := filepath.Join(filepath.Dir(manifestPath), "_locales", locale, "messages.json")
	messages := map[string]struct {
		Message string `json:"message"`
	}{}
	if err := readBoundedJSON(messagesPath, maximumManifestBytes, &messages); err != nil {
		return ""
	}
	for key, value := range messages {
		if strings.EqualFold(key, messageKey) {
			return boundedText(value.Message, 100)
		}
	}
	return ""
}

func scanFirefoxRoot(root browserRoot, browser model.BrowserInstallation) (model.BrowserInstallation, bool, bool) {
	entries, truncated, err := readDirectoryBounded(root.path, maximumBrowserProfiles*4)
	if err != nil {
		return browser, true, true
	}
	accumulators := map[string]*extensionAccumulator{}
	partial := truncated
	profiles := 0
	for _, entry := range entries {
		if !entry.IsDir() || profiles >= maximumBrowserProfiles {
			continue
		}
		statePath := filepath.Join(root.path, entry.Name(), "extensions.json")
		if !exists(statePath) {
			continue
		}
		profiles++
		var state firefoxExtensionState
		if err := readBoundedJSON(statePath, maximumFirefoxStateBytes, &state); err != nil {
			partial = true
			continue
		}
		for _, addon := range state.Addons {
			if addon.Hidden || addon.Type != "extension" || strings.TrimSpace(addon.ID) == "" {
				continue
			}
			extensionState := "disabled"
			if addon.Active {
				extensionState = "active"
			}
			name := boundedText(addon.DefaultLocale.Name, 100)
			if name == "" {
				name = "Unnamed extension"
			}
			extension := model.BrowserExtension{
				Fingerprint:                  extensionFingerprint(root.id, addon.ID),
				Name:                         name,
				Version:                      boundedText(addon.Version, 40),
				State:                        extensionState,
				SiteAccess:                   siteAccess(addon.UserPermissions.Origins),
				OptionalSiteAccess:           siteAccess(addon.OptionalPermissions.Origins),
				SensitivePermissions:         sensitivePermissions(addon.UserPermissions.Permissions),
				OptionalSensitivePermissions: sensitivePermissions(addon.OptionalPermissions.Permissions),
			}
			accumulateExtension(accumulators, entry.Name(), extension)
		}
		if browser.Version == "" {
			browser.Version = firefoxProfileVersion(filepath.Join(root.path, entry.Name(), "compatibility.ini"))
		}
	}
	browser.ProfileCount = profiles
	browser.Extensions = accumulatedExtensions(accumulators)
	if len(browser.Extensions) > maximumBrowserExtensions {
		browser.Extensions = browser.Extensions[:maximumBrowserExtensions]
		partial = true
	}
	return browser, true, partial
}

func firefoxProfileVersion(path string) string {
	contents, err := readBoundedText(path, 64<<10)
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(contents, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "LastVersion=") {
			value := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "LastVersion="))
			if index := strings.IndexByte(value, '_'); index >= 0 {
				value = value[:index]
			}
			return boundedText(value, 40)
		}
	}
	return ""
}

func accumulateExtension(accumulators map[string]*extensionAccumulator, profileKey string, extension model.BrowserExtension) {
	accumulator := accumulators[extension.Fingerprint]
	if accumulator == nil {
		accumulator = &extensionAccumulator{extension: extension, profiles: map[string]struct{}{}}
		accumulators[extension.Fingerprint] = accumulator
	}
	accumulator.profiles[profileKey] = struct{}{}
	accumulator.extension.ProfileCount = len(accumulator.profiles)
	if extension.Version > accumulator.extension.Version {
		accumulator.extension.Version = extension.Version
	}
	if extension.State == "active" {
		accumulator.extension.State = "active"
	}
}

func accumulatedExtensions(accumulators map[string]*extensionAccumulator) []model.BrowserExtension {
	extensions := make([]model.BrowserExtension, 0, len(accumulators))
	for _, accumulator := range accumulators {
		extensions = append(extensions, accumulator.extension)
	}
	sort.Slice(extensions, func(left, right int) bool {
		if extensions[left].Name == extensions[right].Name {
			return extensions[left].Fingerprint < extensions[right].Fingerprint
		}
		return strings.ToLower(extensions[left].Name) < strings.ToLower(extensions[right].Name)
	})
	return extensions
}

func hostPatterns(values []string) []string {
	patterns := []string{}
	for _, value := range values {
		if value == "<all_urls>" || strings.Contains(value, "://") {
			patterns = append(patterns, value)
		}
	}
	return patterns
}

func contentScriptMatches(manifest browserExtensionManifest) []string {
	patterns := []string{}
	for _, script := range manifest.ContentScripts {
		patterns = append(patterns, script.Matches...)
	}
	return patterns
}

func siteAccess(patterns []string) string {
	if len(patterns) == 0 {
		return "none-declared"
	}
	for _, pattern := range patterns {
		normalized := strings.ToLower(strings.TrimSpace(pattern))
		if normalized == "<all_urls>" || normalized == "*://*/*" || normalized == "http://*/*" || normalized == "https://*/*" {
			return "all-sites"
		}
	}
	return "specific-sites"
}

func sensitivePermissions(values []string) []string {
	seen := map[string]string{}
	for _, value := range values {
		normalized := strings.ToLower(strings.TrimSpace(value))
		if _, allowed := sensitiveBrowserPermissions[normalized]; allowed {
			seen[normalized] = boundedText(strings.TrimSpace(value), 40)
		}
	}
	result := make([]string, 0, len(seen))
	for _, value := range seen {
		result = append(result, value)
	}
	sort.Slice(result, func(left, right int) bool { return strings.ToLower(result[left]) < strings.ToLower(result[right]) })
	if len(result) > 24 {
		return result[:24]
	}
	return result
}

func extensionFingerprint(browserID, extensionID string) string {
	digest := sha256.Sum256([]byte(browserID + "\x00" + extensionID))
	return hex.EncodeToString(digest[:12])
}

func readBoundedJSON(path string, maximum int64, destination any) error {
	contents, err := readBoundedBytes(path, maximum)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(contents))
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("browser metadata contains multiple JSON values")
		}
		return err
	}
	return nil
}

func readBoundedText(path string, maximum int64) (string, error) {
	contents, err := readBoundedBytes(path, maximum)
	return string(contents), err
}

func readBoundedBytes(path string, maximum int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	contents, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil {
		return nil, err
	}
	if int64(len(contents)) > maximum {
		return nil, errors.New("browser metadata exceeds the collection limit")
	}
	return contents, nil
}

func readDirectoryBounded(path string, maximum int) ([]fs.DirEntry, bool, error) {
	directory, err := os.Open(path)
	if err != nil {
		return nil, false, err
	}
	defer directory.Close()
	entries, err := directory.ReadDir(maximum + 1)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, false, err
	}
	if len(entries) > maximum {
		return entries[:maximum], true, nil
	}
	return entries, false, nil
}

func isChromiumUserProfile(name string) bool {
	if name == "Default" {
		return true
	}
	if !strings.HasPrefix(name, "Profile ") {
		return false
	}
	number, err := strconv.Atoi(strings.TrimPrefix(name, "Profile "))
	return err == nil && number > 0
}

func compareBrowserVersions(left, right string) int {
	leftParts := strings.Split(left, ".")
	rightParts := strings.Split(right, ".")
	length := len(leftParts)
	if len(rightParts) > length {
		length = len(rightParts)
	}
	for index := 0; index < length; index++ {
		leftPart, rightPart := 0, 0
		if index < len(leftParts) {
			leftPart, _ = strconv.Atoi(strings.TrimLeft(leftParts[index], "v"))
		}
		if index < len(rightParts) {
			rightPart, _ = strconv.Atoi(strings.TrimLeft(rightParts[index], "v"))
		}
		if leftPart > rightPart {
			return 1
		}
		if leftPart < rightPart {
			return -1
		}
	}
	return strings.Compare(left, right)
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func boundedText(value string, maximum int) string {
	value = strings.TrimSpace(strings.Map(func(character rune) rune {
		if unicode.IsControl(character) {
			return ' '
		}
		return character
	}, value))
	runes := []rune(value)
	if len(runes) > maximum {
		value = string(runes[:maximum])
	}
	return strings.TrimSpace(value)
}

func boundedToken(value string, maximum int) string {
	value = boundedText(value, maximum)
	for _, character := range value {
		if !(unicode.IsLetter(character) || unicode.IsDigit(character) || character == '_' || character == '-') {
			return ""
		}
	}
	return value
}
