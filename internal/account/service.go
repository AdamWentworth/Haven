// Package account owns HAVEN's encrypted, owner-reported account-security
// notebook. It deliberately has no provider login, OAuth token, password,
// recovery-code, or authenticator-secret field.
package account

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/AdamWentworth/haven/internal/storage"
)

const (
	maximumProfiles      = 250
	maximumReviewDetails = 16
	maximumNotesBytes    = 4 * 1024
	reviewAge            = 180 * 24 * time.Hour
)

var (
	ErrInvalidProfile = errors.New("account profile is invalid")
	ErrProfileLimit   = errors.New("account profile limit reached")
)

type ProfileInput struct {
	ID                string     `json:"id,omitempty"`
	Provider          string     `json:"provider"`
	Label             string     `json:"label"`
	Identifier        string     `json:"identifier,omitempty"`
	Category          string     `json:"category"`
	TwoStepStatus     string     `json:"twoStepStatus"`
	Factors           []string   `json:"factors"`
	PasswordStatus    string     `json:"passwordStatus"`
	RecoveryStatus    string     `json:"recoveryStatus"`
	BackupCodesStatus string     `json:"backupCodesStatus"`
	LastReviewedAt    *time.Time `json:"lastReviewedAt,omitempty"`
	ReviewDetails     []string   `json:"reviewDetails,omitempty"`
	Notes             string     `json:"notes,omitempty"`
}

type Suggestion struct {
	ID       string `json:"id"`
	Priority string `json:"priority"`
	Title    string `json:"title"`
	Summary  string `json:"summary"`
}

type Profile struct {
	ProfileInput
	Status      string       `json:"status"`
	Suggestions []Suggestion `json:"suggestions"`
	CreatedAt   time.Time    `json:"createdAt"`
	UpdatedAt   time.Time    `json:"updatedAt"`
}

type storedProfile struct {
	Provider          string     `json:"provider"`
	Label             string     `json:"label"`
	Identifier        string     `json:"identifier,omitempty"`
	Category          string     `json:"category"`
	TwoStepStatus     string     `json:"twoStepStatus"`
	Factors           []string   `json:"factors"`
	PasswordStatus    string     `json:"passwordStatus"`
	RecoveryStatus    string     `json:"recoveryStatus"`
	BackupCodesStatus string     `json:"backupCodesStatus"`
	LastReviewedAt    *time.Time `json:"lastReviewedAt,omitempty"`
	ReviewDetails     []string   `json:"reviewDetails,omitempty"`
	Notes             string     `json:"notes,omitempty"`
}

type Service struct {
	store *storage.Store
	key   []byte
}

func New(store *storage.Store, keyPath string) (*Service, error) {
	if store == nil {
		return nil, errors.New("account notebook storage is required")
	}
	key, err := loadOrCreateKey(keyPath)
	if err != nil {
		return nil, fmt.Errorf("configure account notebook encryption: %w", err)
	}
	return &Service{store: store, key: key}, nil
}

func (service *Service) List(ctx context.Context, now time.Time) ([]Profile, error) {
	records, err := service.store.ListEncryptedAccountProfiles(ctx)
	if err != nil {
		return nil, err
	}
	profiles := make([]Profile, 0, len(records))
	for _, record := range records {
		profile, err := service.decrypt(record, now)
		if err != nil {
			return nil, fmt.Errorf("open account profile %q: %w", record.ID, err)
		}
		profiles = append(profiles, profile)
	}
	sort.SliceStable(profiles, func(i, j int) bool {
		left := strings.ToLower(profiles[i].Provider + "\x00" + profiles[i].Label)
		right := strings.ToLower(profiles[j].Provider + "\x00" + profiles[j].Label)
		return left < right
	})
	return profiles, nil
}

func (service *Service) Save(ctx context.Context, input ProfileInput, now time.Time) (Profile, error) {
	now = now.UTC()
	input, err := normalize(input, now)
	if err != nil {
		return Profile{}, err
	}
	createdAt := now
	if input.ID == "" {
		records, err := service.store.ListEncryptedAccountProfiles(ctx)
		if err != nil {
			return Profile{}, err
		}
		if len(records) >= maximumProfiles {
			return Profile{}, ErrProfileLimit
		}
		input.ID, err = randomID()
		if err != nil {
			return Profile{}, err
		}
	} else {
		if !validID(input.ID) {
			return Profile{}, ErrInvalidProfile
		}
		existing, err := service.store.EncryptedAccountProfile(ctx, input.ID)
		if err != nil {
			return Profile{}, err
		}
		createdAt = existing.CreatedAt
	}

	payload := storedProfile{
		Provider: input.Provider, Label: input.Label, Identifier: input.Identifier,
		Category: input.Category, TwoStepStatus: input.TwoStepStatus,
		Factors: input.Factors, PasswordStatus: input.PasswordStatus,
		RecoveryStatus: input.RecoveryStatus, BackupCodesStatus: input.BackupCodesStatus,
		LastReviewedAt: input.LastReviewedAt, ReviewDetails: input.ReviewDetails, Notes: input.Notes,
	}
	plain, err := json.Marshal(payload)
	if err != nil {
		return Profile{}, err
	}
	ciphertext, err := service.seal(input.ID, plain)
	if err != nil {
		return Profile{}, err
	}
	record := storage.EncryptedAccountProfile{ID: input.ID, Ciphertext: ciphertext, CreatedAt: createdAt, UpdatedAt: now}
	if err := service.store.SaveEncryptedAccountProfile(ctx, record); err != nil {
		return Profile{}, err
	}
	return present(input, createdAt, now, now), nil
}

func (service *Service) Delete(ctx context.Context, id string) error {
	if !validID(id) {
		return ErrInvalidProfile
	}
	return service.store.DeleteAccountProfile(ctx, id)
}

func (service *Service) decrypt(record storage.EncryptedAccountProfile, now time.Time) (Profile, error) {
	plain, err := service.open(record.ID, record.Ciphertext)
	if err != nil {
		return Profile{}, err
	}
	var payload storedProfile
	decoder := json.NewDecoder(strings.NewReader(string(plain)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&payload); err != nil {
		return Profile{}, errors.New("stored account profile is invalid")
	}
	input, err := normalize(ProfileInput{
		ID: record.ID, Provider: payload.Provider, Label: payload.Label,
		Identifier: payload.Identifier, Category: payload.Category,
		TwoStepStatus: payload.TwoStepStatus, Factors: payload.Factors,
		PasswordStatus: payload.PasswordStatus, RecoveryStatus: payload.RecoveryStatus,
		BackupCodesStatus: payload.BackupCodesStatus, LastReviewedAt: payload.LastReviewedAt,
		ReviewDetails: payload.ReviewDetails,
		Notes:         payload.Notes,
	}, now)
	if err != nil {
		return Profile{}, errors.New("stored account profile is invalid")
	}
	return present(input, record.CreatedAt, record.UpdatedAt, now), nil
}

func present(input ProfileInput, createdAt, updatedAt, now time.Time) Profile {
	suggestions := suggestions(input, now)
	status := "good"
	for _, suggestion := range suggestions {
		if suggestion.Priority == "high" || suggestion.Priority == "medium" {
			status = "attention"
			break
		}
		status = "incomplete"
	}
	return Profile{ProfileInput: input, Status: status, Suggestions: suggestions, CreatedAt: createdAt, UpdatedAt: updatedAt}
}

func suggestions(input ProfileInput, now time.Time) []Suggestion {
	result := []Suggestion{}
	add := func(id, priority, title, summary string) {
		result = append(result, Suggestion{ID: id, Priority: priority, Title: title, Summary: summary})
	}
	if input.TwoStepStatus == "disabled" {
		add("enable-two-step", "high", "Enable two-step verification", input.Provider+" is recorded without two-step verification. Add a second factor in the provider's own security settings.")
	}
	if input.PasswordStatus == "reused" {
		add("replace-reused-password", "high", "Use a unique password", "A reused password lets a breach at another service endanger this profile. Replace it with a unique password stored in your password manager.")
	}
	if input.RecoveryStatus == "missing" {
		add("add-recovery-method", "medium", "Add a recovery method", "Record a verified recovery email, phone, or provider-supported recovery method in the provider's own settings.")
	}
	if input.TwoStepStatus == "enabled" && input.BackupCodesStatus == "missing" {
		add("store-backup-codes", "medium", "Generate and store backup codes", "Keep the actual codes outside HAVEN in a secure offline location or password manager.")
	}
	if input.TwoStepStatus == "enabled" && len(input.Factors) == 0 {
		add("record-second-factor", "low", "Record the second-factor method", "Two-step verification is enabled, but its method is not recorded yet. Confirm the method at the provider when convenient.")
	}
	if input.TwoStepStatus == "enabled" && weakFactorsOnly(input.Factors) {
		add("strengthen-second-factor", "medium", "Add a stronger second factor", "SMS or email-only verification is more exposed to account and carrier takeover. Prefer an authenticator, passkey, or hardware security key when supported.")
	}
	unknown := input.TwoStepStatus == "unknown" || input.PasswordStatus == "unknown" || input.RecoveryStatus == "unknown" || input.BackupCodesStatus == "unknown"
	if unknown {
		add("complete-checklist", "low", "Complete the security checklist", "One or more security measures are still marked unknown. Check the provider directly when convenient.")
	}
	if input.LastReviewedAt == nil {
		add("record-review", "low", "Record a security review", "Review active sessions and recovery details at the provider, then record the date here.")
	} else if now.Sub(input.LastReviewedAt.UTC()) > reviewAge {
		add("review-sessions", "low", "Review sessions and recovery details", "This profile has not been reviewed in more than six months. Check signed-in devices and recovery methods at the provider.")
	}
	return result
}

func weakFactorsOnly(factors []string) bool {
	if len(factors) == 0 {
		return false
	}
	for _, factor := range factors {
		if factor != "sms" && factor != "email" {
			return false
		}
	}
	return true
}

func normalize(input ProfileInput, now time.Time) (ProfileInput, error) {
	input.ID = strings.TrimSpace(input.ID)
	input.Provider = strings.TrimSpace(input.Provider)
	input.Label = strings.TrimSpace(input.Label)
	input.Identifier = strings.TrimSpace(input.Identifier)
	input.Category = strings.ToLower(strings.TrimSpace(input.Category))
	input.TwoStepStatus = strings.ToLower(strings.TrimSpace(input.TwoStepStatus))
	input.PasswordStatus = strings.ToLower(strings.TrimSpace(input.PasswordStatus))
	input.RecoveryStatus = strings.ToLower(strings.TrimSpace(input.RecoveryStatus))
	input.BackupCodesStatus = strings.ToLower(strings.TrimSpace(input.BackupCodesStatus))
	input.Notes = strings.TrimSpace(input.Notes)
	if input.ReviewDetails == nil {
		input.ReviewDetails = []string{}
	}
	if input.Factors == nil {
		input.Factors = []string{}
	}
	if !boundedLine(input.Provider, 80) || !boundedLine(input.Label, 120) || len(input.Identifier) > 200 || strings.ContainsAny(input.Identifier, "\r\n\x00") || len(input.Notes) > maximumNotesBytes || strings.ContainsRune(input.Notes, '\x00') {
		return input, ErrInvalidProfile
	}
	if !oneOf(input.Category, "email", "social", "developer", "finance", "gaming", "shopping", "work", "other") ||
		!oneOf(input.TwoStepStatus, "unknown", "enabled", "disabled", "not-supported") ||
		!oneOf(input.PasswordStatus, "unknown", "unique", "reused", "passwordless", "not-applicable") ||
		!oneOf(input.RecoveryStatus, "unknown", "configured", "missing", "not-supported") ||
		!oneOf(input.BackupCodesStatus, "unknown", "stored", "missing", "not-supported") {
		return input, ErrInvalidProfile
	}
	if len(input.Factors) > 8 {
		return input, ErrInvalidProfile
	}
	seen := map[string]bool{}
	for index, factor := range input.Factors {
		factor = strings.ToLower(strings.TrimSpace(factor))
		if !oneOf(factor, "authenticator", "passkey", "security-key", "provider-prompt", "sms", "email", "other") || seen[factor] {
			return input, ErrInvalidProfile
		}
		seen[factor] = true
		input.Factors[index] = factor
	}
	sort.Strings(input.Factors)
	cleanDetails := make([]string, 0, len(input.ReviewDetails))
	seenDetails := map[string]bool{}
	for _, detail := range input.ReviewDetails {
		detail = strings.TrimSpace(detail)
		if detail == "" {
			continue
		}
		key := strings.ToLower(detail)
		if !boundedLine(detail, 240) || containsSecretMaterial(detail) || seenDetails[key] {
			return input, ErrInvalidProfile
		}
		seenDetails[key] = true
		cleanDetails = append(cleanDetails, detail)
		if len(cleanDetails) > maximumReviewDetails {
			return input, ErrInvalidProfile
		}
	}
	input.ReviewDetails = cleanDetails
	if input.TwoStepStatus != "enabled" && len(input.Factors) > 0 {
		return input, ErrInvalidProfile
	}
	if input.LastReviewedAt != nil {
		reviewed := input.LastReviewedAt.UTC()
		if reviewed.Before(time.Date(2000, time.January, 1, 0, 0, 0, 0, time.UTC)) || reviewed.After(now.Add(24*time.Hour)) {
			return input, ErrInvalidProfile
		}
		input.LastReviewedAt = &reviewed
	}
	if containsSecretMaterial(input.Identifier) || containsSecretMaterial(input.Notes) {
		return input, ErrInvalidProfile
	}
	return input, nil
}

func containsSecretMaterial(value string) bool {
	lower := strings.ToLower(value)
	privateKeyPrefix := "-----begin "
	for _, marker := range []string{"otpauth://", privateKeyPrefix + "private key-----", privateKeyPrefix + "rsa private key-----", privateKeyPrefix + "ec private key-----", privateKeyPrefix + "openssh private key-----", "set-cookie:", "cookie:"} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func boundedLine(value string, maximum int) bool {
	return value != "" && len(value) <= maximum && !strings.ContainsAny(value, "\r\n\t\x00")
}

func oneOf(value string, allowed ...string) bool {
	for _, item := range allowed {
		if value == item {
			return true
		}
	}
	return false
}

func validID(value string) bool {
	if len(value) != 29 || !strings.HasPrefix(value, "acct_") {
		return false
	}
	for _, character := range value[len("acct_"):] {
		if (character < 'a' || character > 'z') && (character < 'A' || character > 'Z') && (character < '0' || character > '9') && character != '-' && character != '_' {
			return false
		}
	}
	return true
}

func randomID() (string, error) {
	value := make([]byte, 18)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return "acct_" + base64.RawURLEncoding.EncodeToString(value), nil
}

func (service *Service) seal(id string, plain []byte) ([]byte, error) {
	gcm, err := service.gcm()
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plain, []byte("HAVEN account profile v1:"+id)), nil
}

func (service *Service) open(id string, value []byte) ([]byte, error) {
	gcm, err := service.gcm()
	if err != nil {
		return nil, err
	}
	if len(value) < gcm.NonceSize() {
		return nil, errors.New("stored account profile is invalid")
	}
	plain, err := gcm.Open(nil, value[:gcm.NonceSize()], value[gcm.NonceSize():], []byte("HAVEN account profile v1:"+id))
	if err != nil {
		return nil, errors.New("stored account profile could not be decrypted")
	}
	return plain, nil
}

func (service *Service) gcm() (cipher.AEAD, error) {
	block, err := aes.NewCipher(service.key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func loadOrCreateKey(path string) ([]byte, error) {
	if path == "" {
		return nil, errors.New("account notebook key path is required")
	}
	if value, err := os.ReadFile(path); err == nil {
		if len(value) != 32 {
			return nil, errors.New("account notebook encryption key has an invalid length")
		}
		return value, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	value := make([]byte, 32)
	if _, err := rand.Read(value); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			value, err := os.ReadFile(path)
			if err != nil || len(value) != 32 {
				return nil, errors.New("account notebook encryption key has an invalid length")
			}
			return value, nil
		}
		return nil, err
	}
	if _, err := file.Write(value); err != nil {
		file.Close()
		return nil, err
	}
	if err := file.Close(); err != nil {
		return nil, err
	}
	return value, nil
}

// DemoProfiles returns invented portfolio fixtures without touching private
// account storage.
func DemoProfiles(now time.Time) []Profile {
	reviewed := now.UTC().Add(-21 * 24 * time.Hour)
	inputs := []ProfileInput{
		{ID: "acct_demo_google_profile", Provider: "Google", Label: "Personal account", Category: "email", TwoStepStatus: "enabled", Factors: []string{"authenticator", "passkey"}, PasswordStatus: "unique", RecoveryStatus: "configured", BackupCodesStatus: "stored", LastReviewedAt: &reviewed, ReviewDetails: []string{"Signed-in devices were reviewed.", "Backup codes are stored outside HAVEN."}},
		{ID: "acct_demo_social_profile", Provider: "Example Social", Label: "Portfolio profile", Category: "social", TwoStepStatus: "disabled", Factors: []string{}, PasswordStatus: "unique", RecoveryStatus: "configured", BackupCodesStatus: "not-supported", LastReviewedAt: &reviewed, Notes: "Enable two-step verification next."},
	}
	profiles := make([]Profile, 0, len(inputs))
	for index, input := range inputs {
		created := now.UTC().Add(-time.Duration(index+30) * 24 * time.Hour)
		profiles = append(profiles, present(input, created, reviewed, now.UTC()))
	}
	return profiles
}
