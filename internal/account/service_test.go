package account

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/AdamWentworth/haven/internal/storage"
)

func testService(t *testing.T) (*Service, *storage.Store) {
	t.Helper()
	directory := t.TempDir()
	store, err := storage.Open(context.Background(), filepath.Join(directory, "haven.db"))
	if err != nil {
		t.Fatal(err)
	}
	service, err := New(store, filepath.Join(directory, "account-notes.key"))
	if err != nil {
		store.Close()
		t.Fatal(err)
	}
	return service, store
}

func completeInput(now time.Time) ProfileInput {
	reviewed := now.Add(-24 * time.Hour)
	return ProfileInput{
		Provider: "Google", Label: "Personal", Identifier: "owner@example.com",
		Category: "email", TwoStepStatus: "enabled",
		Factors: []string{"passkey", "authenticator"}, PasswordStatus: "unique",
		RecoveryStatus: "configured", BackupCodesStatus: "stored",
		LastReviewedAt: &reviewed, SessionStatus: "recognized", SessionReviewedAt: &reviewed,
		SessionChecks: []string{"devices", "recent-activity", "third-party-access", "unused-sessions"},
		ReviewDetails: []string{"Signed-in devices reviewed; nothing unfamiliar.", "Recovery methods are current."},
		Notes:         "Enhanced protection remains an owner choice.",
	}
}

func TestProfilesAreEncryptedAndRoundTrip(t *testing.T) {
	service, store := testService(t)
	defer store.Close()
	ctx := context.Background()
	now := time.Date(2026, time.September, 4, 18, 0, 0, 0, time.UTC)

	created, err := service.Save(ctx, completeInput(now), now)
	if err != nil {
		t.Fatal(err)
	}
	if created.ID == "" || created.Status != "good" || len(created.Suggestions) != 0 {
		t.Fatalf("unexpected presented profile: %#v", created)
	}
	records, err := store.ListEncryptedAccountProfiles(ctx)
	if err != nil || len(records) != 1 {
		t.Fatalf("unexpected encrypted records: %#v, %v", records, err)
	}
	for _, forbidden := range [][]byte{[]byte("Google"), []byte("owner@example.com"), []byte("Signed-in devices"), []byte("Enhanced protection"), []byte("third-party-access"), []byte("recognized")} {
		if bytes.Contains(records[0].Ciphertext, forbidden) {
			t.Fatalf("ciphertext exposed account material %q", forbidden)
		}
	}

	listed, err := service.List(ctx, now)
	if err != nil || len(listed) != 1 || listed[0].Identifier != "owner@example.com" || len(listed[0].ReviewDetails) != 2 || listed[0].SessionStatus != "recognized" || len(listed[0].SessionChecks) != 4 {
		t.Fatalf("unexpected decrypted profiles: %#v, %v", listed, err)
	}
	updatedInput := listed[0].ProfileInput
	updatedInput.Notes = "Updated private note."
	updated, err := service.Save(ctx, updatedInput, now.Add(time.Hour))
	if err != nil || updated.CreatedAt != created.CreatedAt || updated.UpdatedAt.Equal(created.UpdatedAt) {
		t.Fatalf("update did not preserve lifecycle: %#v, %v", updated, err)
	}
	if err := service.Delete(ctx, created.ID); err != nil {
		t.Fatal(err)
	}
	if err := service.Delete(ctx, created.ID); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("expected missing profile after deletion, got %v", err)
	}
}

func TestLegacyEncryptedProfileDefaultsSessionReviewToUnknown(t *testing.T) {
	service, store := testService(t)
	defer store.Close()
	ctx := context.Background()
	now := time.Date(2026, time.September, 4, 18, 0, 0, 0, time.UTC)
	id := "acct_AAAAAAAAAAAAAAAAAAAAAAAA"
	plain := []byte(`{"provider":"Google","label":"Legacy","category":"email","twoStepStatus":"enabled","factors":["passkey"],"passwordStatus":"unique","recoveryStatus":"configured","backupCodesStatus":"stored"}`)
	ciphertext, err := service.seal(id, plain)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveEncryptedAccountProfile(ctx, storage.EncryptedAccountProfile{ID: id, Ciphertext: ciphertext, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	profiles, err := service.List(ctx, now)
	if err != nil || len(profiles) != 1 {
		t.Fatalf("legacy profile did not load: %#v, %v", profiles, err)
	}
	if profiles[0].SessionStatus != "unknown" || profiles[0].SessionReviewedAt != nil || len(profiles[0].SessionChecks) != 0 {
		t.Fatalf("legacy session fields did not default safely: %#v", profiles[0])
	}
}

func TestProfileSuggestionsRemainCalmAndFactBased(t *testing.T) {
	now := time.Date(2026, time.September, 4, 18, 0, 0, 0, time.UTC)
	input := completeInput(now)
	input.TwoStepStatus = "disabled"
	input.Factors = []string{}
	input.PasswordStatus = "reused"
	input.RecoveryStatus = "missing"
	input.BackupCodesStatus = "missing"
	input.LastReviewedAt = nil
	profile := present(input, now, now, now)
	if profile.Status != "attention" {
		t.Fatalf("expected improvement suggestions, got %#v", profile)
	}
	ids := map[string]bool{}
	for _, suggestion := range profile.Suggestions {
		ids[suggestion.ID] = true
	}
	if !ids["enable-two-step"] || !ids["replace-reused-password"] || !ids["add-recovery-method"] || !ids["record-review"] {
		t.Fatalf("missing evidence-derived suggestions: %#v", profile.Suggestions)
	}
	if ids["store-backup-codes"] {
		t.Fatal("backup-code advice must not require codes before two-step verification is enabled")
	}
}

func TestSMSOnlyAndOldReviewProduceSuggestions(t *testing.T) {
	now := time.Date(2026, time.September, 4, 18, 0, 0, 0, time.UTC)
	input := completeInput(now)
	input.Factors = []string{"sms"}
	input.BackupCodesStatus = "missing"
	old := now.Add(-181 * 24 * time.Hour)
	input.LastReviewedAt = &old
	profile := present(input, now, now, now)
	ids := map[string]bool{}
	for _, suggestion := range profile.Suggestions {
		ids[suggestion.ID] = true
	}
	if !ids["strengthen-second-factor"] || !ids["store-backup-codes"] || !ids["review-sessions"] {
		t.Fatalf("missing expected suggestions: %#v", profile.Suggestions)
	}
}

func TestEnabledTwoStepWithoutRecordedFactorRemainsIncomplete(t *testing.T) {
	now := time.Date(2026, time.September, 4, 18, 0, 0, 0, time.UTC)
	input := completeInput(now)
	input.Factors = []string{}
	profile := present(input, now, now, now)
	if profile.Status != "incomplete" || len(profile.Suggestions) != 1 || profile.Suggestions[0].ID != "record-second-factor" || profile.Suggestions[0].Priority != "low" {
		t.Fatalf("enabled two-step without a recorded factor must remain an informational checklist gap: %#v", profile)
	}
}

func TestSessionReviewSuggestionsFollowRecordedEvidence(t *testing.T) {
	now := time.Date(2026, time.September, 4, 18, 0, 0, 0, time.UTC)
	tests := []struct {
		name     string
		mutate   func(*ProfileInput)
		wantID   string
		priority string
	}{
		{name: "not checked", mutate: func(input *ProfileInput) {
			input.SessionStatus = "unknown"
			input.SessionReviewedAt = nil
			input.SessionChecks = nil
		}, wantID: "review-provider-sessions", priority: "low"},
		{name: "unfamiliar", mutate: func(input *ProfileInput) { input.SessionStatus = "attention" }, wantID: "secure-unfamiliar-session", priority: "high"},
		{name: "stale", mutate: func(input *ProfileInput) {
			reviewed := now.Add(-91 * 24 * time.Hour)
			input.SessionReviewedAt = &reviewed
		}, wantID: "refresh-session-review", priority: "low"},
		{name: "incomplete", mutate: func(input *ProfileInput) { input.SessionChecks = []string{"devices"} }, wantID: "complete-session-review", priority: "low"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := completeInput(now)
			test.mutate(&input)
			profile := present(input, now, now, now)
			found := false
			for _, suggestion := range profile.Suggestions {
				if suggestion.ID == test.wantID && suggestion.Priority == test.priority {
					found = true
				}
			}
			if !found {
				t.Fatalf("missing %s/%s suggestion: %#v", test.wantID, test.priority, profile.Suggestions)
			}
		})
	}
}

func TestValidationRejectsContradictorySessionReview(t *testing.T) {
	now := time.Date(2026, time.September, 4, 18, 0, 0, 0, time.UTC)
	reviewed := now.Add(-time.Hour)
	tests := []ProfileInput{
		func() ProfileInput {
			input := completeInput(now)
			input.SessionStatus = "unknown"
			input.SessionReviewedAt = &reviewed
			return input
		}(),
		func() ProfileInput {
			input := completeInput(now)
			input.SessionStatus = "not-supported"
			input.SessionChecks = []string{"devices"}
			input.SessionReviewedAt = nil
			return input
		}(),
		func() ProfileInput {
			input := completeInput(now)
			input.SessionChecks = []string{"devices", "devices"}
			return input
		}(),
		func() ProfileInput {
			input := completeInput(now)
			input.SessionChecks = []string{"cookie-values"}
			return input
		}(),
	}
	for index, input := range tests {
		if _, err := normalize(input, now); !errors.Is(err, ErrInvalidProfile) {
			t.Fatalf("case %d should be invalid, got %v", index, err)
		}
	}
}

func TestProfileIdentityIsStrictlyOpaque(t *testing.T) {
	for _, value := range []string{"", "acct_demo_profile", "acct_AAAAAAAAAAAAAAAAAAAAAAA/", "acct_AAAAAAAAAAAAAAAAAAAAAAAA\n"} {
		if validID(value) {
			t.Fatalf("unexpected valid profile identity %q", value)
		}
	}
	if !validID("acct_AAAAAAAAAAAAAAAAAAAAAAAA") {
		t.Fatal("generated-length base64url profile identity should be valid")
	}
}

func TestValidationRejectsContradictionsAndObviousSecrets(t *testing.T) {
	now := time.Date(2026, time.September, 4, 18, 0, 0, 0, time.UTC)
	tests := []ProfileInput{
		{Provider: "", Label: "Profile", Category: "social", TwoStepStatus: "unknown", PasswordStatus: "unknown", RecoveryStatus: "unknown", BackupCodesStatus: "unknown"},
		{Provider: "Google", Label: "Profile", Category: "social", TwoStepStatus: "disabled", Factors: []string{"authenticator"}, PasswordStatus: "unique", RecoveryStatus: "configured", BackupCodesStatus: "missing"},
		{Provider: "Google", Label: "Profile", Category: "social", TwoStepStatus: "enabled", Factors: []string{"authenticator", "authenticator"}, PasswordStatus: "unique", RecoveryStatus: "configured", BackupCodesStatus: "stored"},
		{Provider: "Google", Label: "Profile", Category: "social", TwoStepStatus: "enabled", Factors: []string{"authenticator"}, PasswordStatus: "unique", RecoveryStatus: "configured", BackupCodesStatus: "stored", Notes: "otpauth://totp/do-not-store-this"},
		{Provider: "Google", Label: "Profile", Category: "social", TwoStepStatus: "enabled", Factors: []string{"authenticator"}, PasswordStatus: "unique", RecoveryStatus: "configured", BackupCodesStatus: "stored", ReviewDetails: []string{"cookie: do-not-store-this"}},
		{Provider: "Google", Label: "Profile", Category: "social", TwoStepStatus: "enabled", Factors: []string{"authenticator"}, PasswordStatus: "unique", RecoveryStatus: "configured", BackupCodesStatus: "stored", ReviewDetails: []string{"Duplicate", "duplicate"}},
	}
	for index, input := range tests {
		if _, err := normalize(input, now); !errors.Is(err, ErrInvalidProfile) {
			t.Fatalf("case %d should be invalid, got %v", index, err)
		}
	}
}

func TestCiphertextIsBoundToProfileIdentity(t *testing.T) {
	service, store := testService(t)
	defer store.Close()
	ctx := context.Background()
	now := time.Date(2026, time.September, 4, 18, 0, 0, 0, time.UTC)
	created, err := service.Save(ctx, completeInput(now), now)
	if err != nil {
		t.Fatal(err)
	}
	record, err := store.EncryptedAccountProfile(ctx, created.ID)
	if err != nil {
		t.Fatal(err)
	}
	record.ID = "acct_AAAAAAAAAAAAAAAAAAAAAAAA"
	record.CreatedAt = now
	record.UpdatedAt = now
	if err := store.SaveEncryptedAccountProfile(ctx, record); err != nil {
		t.Fatal(err)
	}
	if _, err := service.List(ctx, now); err == nil {
		t.Fatal("ciphertext copied to another profile identity must not decrypt")
	}
}
