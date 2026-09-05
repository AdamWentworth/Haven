package collector

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/AdamWentworth/haven/internal/model"
	_ "modernc.org/sqlite"
)

const (
	maximumCookieSitesPerProfile  = 256
	maximumCookieSitesTotal       = 1024
	maximumCookieCountPerProfile  = 100000
	maximumProfilePreferences     = 8 << 20
	maximumChromiumLocalState     = 8 << 20
	cookieReadTimeout             = 2 * time.Second
	chromeEpochOffsetMicroseconds = int64(11644473600000000)
)

const chromiumCookieAggregateQuery = `
	SELECT host_key,
	       COUNT(*) AS cookie_count,
	       SUM(CASE WHEN is_persistent = 0 THEN 1 ELSE 0 END) AS session_count,
	       SUM(CASE WHEN is_persistent = 1 THEN 1 ELSE 0 END) AS persistent_count,
	       SUM(CASE WHEN is_secure = 1 THEN 1 ELSE 0 END) AS secure_count,
	       SUM(CASE WHEN is_httponly = 1 THEN 1 ELSE 0 END) AS http_only_count,
	       MAX(last_access_utc) AS last_accessed,
	       MAX(CASE WHEN is_persistent = 1 THEN expires_utc ELSE 0 END) AS latest_expiry
	  FROM cookies
	 WHERE host_key <> ''
	 GROUP BY host_key
	 ORDER BY last_accessed DESC, host_key
	 LIMIT ?`

type chromiumProfilePreferences struct {
	Profile struct {
		Name string `json:"name"`
	} `json:"profile"`
}

type chromiumLocalState struct {
	Profile struct {
		InfoCache map[string]struct {
			Name string `json:"name"`
		} `json:"info_cache"`
	} `json:"profile"`
}

func chromiumProfileNames(localStatePath string) map[string]string {
	result := map[string]string{}
	var state chromiumLocalState
	if err := readBoundedJSON(localStatePath, maximumChromiumLocalState, &state); err != nil {
		return result
	}
	for profileKey, details := range state.Profile.InfoCache {
		if !isChromiumUserProfile(profileKey) {
			continue
		}
		if name := boundedText(details.Name, 100); name != "" {
			result[profileKey] = name
		}
	}
	return result
}

func collectChromiumProfile(browserID, profileKey, profilePath, displayName string) (model.BrowserProfile, bool) {
	profile := model.BrowserProfile{
		Fingerprint:  browserProfileFingerprint(browserID, profileKey),
		Name:         chromiumProfileName(profileKey, displayName, filepath.Join(profilePath, "Preferences")),
		CookieStatus: "observed",
		Sites:        []model.BrowserCookieSite{},
	}
	cookiePath := filepath.Join(profilePath, "Network", "Cookies")
	if _, err := os.Stat(cookiePath); errors.Is(err, os.ErrNotExist) {
		return profile, false
	} else if err != nil {
		profile.CookieStatus = "unavailable"
		return profile, true
	}

	total, sites, truncated, partial, err := readChromiumCookieMetadata(cookiePath)
	if err != nil {
		profile.CookieStatus = "unavailable"
		return profile, true
	}
	profile.CookieCount = total
	profile.Sites = sites
	profile.Truncated = truncated
	if partial || truncated {
		profile.CookieStatus = "partial"
	}
	return profile, partial || truncated
}

func chromiumProfileName(profileKey, displayName, preferencesPath string) string {
	if name := boundedText(displayName, 100); name != "" {
		return name
	}
	var preferences chromiumProfilePreferences
	if err := readBoundedJSON(preferencesPath, maximumProfilePreferences, &preferences); err == nil {
		if name := boundedText(preferences.Profile.Name, 100); name != "" {
			return name
		}
	}
	if profileKey == "Default" {
		return "Default profile"
	}
	return boundedText(profileKey, 100)
}

func browserProfileFingerprint(browserID, profileKey string) string {
	digest := sha256.Sum256([]byte(browserID + "\x00profile\x00" + profileKey))
	return hex.EncodeToString(digest[:12])
}

func readChromiumCookieMetadata(path string) (int, []model.BrowserCookieSite, bool, bool, error) {
	uriPath := filepath.ToSlash(path)
	if filepath.VolumeName(path) != "" && !strings.HasPrefix(uriPath, "/") {
		uriPath = "/" + uriPath
	}
	queryURL := &url.URL{Scheme: "file", Path: uriPath}
	parameters := queryURL.Query()
	parameters.Set("mode", "ro")
	parameters.Set("_pragma", "query_only(1)")
	parameters.Add("_pragma", "busy_timeout(500)")
	queryURL.RawQuery = parameters.Encode()

	database, err := sql.Open("sqlite", queryURL.String())
	if err != nil {
		return 0, nil, false, false, err
	}
	defer database.Close()
	database.SetMaxOpenConns(1)
	database.SetMaxIdleConns(0)

	ctx, cancel := context.WithTimeout(context.Background(), cookieReadTimeout)
	defer cancel()
	var total int64
	if err := database.QueryRowContext(ctx, `SELECT COUNT(*) FROM cookies WHERE host_key <> ''`).Scan(&total); err != nil {
		return 0, nil, false, false, err
	}
	partial := false
	if total < 0 {
		return 0, nil, false, false, errors.New("invalid cookie count")
	}
	if total > maximumCookieCountPerProfile {
		total = maximumCookieCountPerProfile
		partial = true
	}

	rows, err := database.QueryContext(ctx, chromiumCookieAggregateQuery, maximumCookieSitesPerProfile+1)
	if err != nil {
		return 0, nil, false, false, err
	}
	defer rows.Close()

	byDomain := map[string]model.BrowserCookieSite{}
	rowCount := 0
	truncated := false
	for rows.Next() {
		var domain string
		var cookieCount, sessionCount, persistentCount, secureCount, httpOnlyCount, lastAccessed, latestExpiry int64
		if err := rows.Scan(&domain, &cookieCount, &sessionCount, &persistentCount, &secureCount, &httpOnlyCount, &lastAccessed, &latestExpiry); err != nil {
			partial = true
			break
		}
		rowCount++
		if rowCount > maximumCookieSitesPerProfile {
			truncated = true
			break
		}
		domain = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(domain)), ".")
		if !validCollectedCookieDomain(domain) || cookieCount < 1 || cookieCount > 10000 || sessionCount < 0 || persistentCount < 0 || sessionCount+persistentCount != cookieCount || secureCount < 0 || secureCount > cookieCount || httpOnlyCount < 0 || httpOnlyCount > cookieCount {
			partial = true
			continue
		}
		entry := byDomain[domain]
		entry.Domain = domain
		entry.CookieCount += int(cookieCount)
		entry.SessionCookieCount += int(sessionCount)
		entry.PersistentCookieCount += int(persistentCount)
		entry.SecureCookieCount += int(secureCount)
		entry.HTTPOnlyCookieCount += int(httpOnlyCount)
		entry.LastAccessedAt = newestTime(entry.LastAccessedAt, chromeTimestamp(lastAccessed))
		entry.LatestExpiryAt = newestTime(entry.LatestExpiryAt, chromeTimestamp(latestExpiry))
		byDomain[domain] = entry
	}
	if err := rows.Err(); err != nil {
		partial = true
	}

	sites := make([]model.BrowserCookieSite, 0, len(byDomain))
	for _, site := range byDomain {
		if site.CookieCount > 10000 {
			partial = true
			continue
		}
		sites = append(sites, site)
	}
	sort.Slice(sites, func(left, right int) bool {
		leftTime, rightTime := time.Time{}, time.Time{}
		if sites[left].LastAccessedAt != nil {
			leftTime = *sites[left].LastAccessedAt
		}
		if sites[right].LastAccessedAt != nil {
			rightTime = *sites[right].LastAccessedAt
		}
		if !leftTime.Equal(rightTime) {
			return leftTime.After(rightTime)
		}
		return sites[left].Domain < sites[right].Domain
	})
	return int(total), sites, truncated, partial, nil
}

func validCollectedCookieDomain(value string) bool {
	if value == "" || len(value) > 253 || strings.Contains(value, "..") {
		return false
	}
	for _, character := range value {
		if !((character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') || character == '.' || character == '-') {
			return false
		}
	}
	return value[0] != '.' && value[len(value)-1] != '.' && value[0] != '-' && value[len(value)-1] != '-'
}

func chromeTimestamp(value int64) *time.Time {
	if value <= chromeEpochOffsetMicroseconds {
		return nil
	}
	converted := time.UnixMicro(value - chromeEpochOffsetMicroseconds).UTC()
	if converted.Before(time.Date(2000, time.January, 1, 0, 0, 0, 0, time.UTC)) || !converted.Before(time.Date(2101, time.January, 1, 0, 0, 0, 0, time.UTC)) {
		return nil
	}
	return &converted
}

func newestTime(left, right *time.Time) *time.Time {
	if right == nil {
		return left
	}
	if left == nil || right.After(*left) {
		value := right.UTC()
		return &value
	}
	return left
}
