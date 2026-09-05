package browserreview

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/AdamWentworth/haven/internal/model"
	"github.com/AdamWentworth/haven/internal/storage"
)

func reviewTestStore(t *testing.T) (*storage.Store, string) {
	t.Helper()
	directory := t.TempDir()
	databasePath := filepath.Join(directory, "haven.db")
	store, err := storage.Open(context.Background(), databasePath)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := model.SecuritySnapshot{
		CollectedAt:      time.Now().UTC(),
		Device:           model.DeviceSummary{DeviceID: "test-device", HostName: "test-device", OperatingSystem: "test"},
		FirewallProfiles: []model.FirewallProfileStatus{},
		Connections:      []model.NetworkConnection{},
		Notices:          []model.CollectorNotice{},
	}
	if err := store.SaveSnapshot(context.Background(), snapshot); err != nil {
		store.Close()
		t.Fatal(err)
	}
	return store, directory
}

func testReview(state string) ReviewInput {
	return ReviewInput{
		ReviewKey: ReviewKey{
			DeviceID:           "test-device",
			BrowserID:          "chrome",
			ProfileFingerprint: "abcdef0123456789abcdef01",
			Domain:             "accounts.example.test",
		},
		State: state,
	}
}

func TestServicePersistsUpdatesAndRemovesEncryptedReviews(t *testing.T) {
	store, directory := reviewTestStore(t)
	defer store.Close()
	service, err := New(store, filepath.Join(directory, "browser-site-reviews.key"))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	firstAt := time.Date(2026, time.September, 5, 8, 0, 0, 0, time.UTC)
	first, err := service.Save(ctx, testReview(StateSignedInKeep), firstAt)
	if err != nil {
		t.Fatal(err)
	}
	if first.State != StateSignedInKeep || !first.ReviewedAt.Equal(firstAt) {
		t.Fatalf("unexpected saved review: %#v", first)
	}

	updatedAt := firstAt.Add(time.Hour)
	updated, err := service.Save(ctx, testReview(StateClearCandidate), updatedAt)
	if err != nil {
		t.Fatal(err)
	}
	if updated.State != StateClearCandidate || !updated.ReviewedAt.Equal(updatedAt) {
		t.Fatalf("unexpected updated review: %#v", updated)
	}
	reviews, err := service.List(ctx, "test-device")
	if err != nil {
		t.Fatal(err)
	}
	if len(reviews) != 1 || reviews[0].Domain != "accounts.example.test" || reviews[0].State != StateClearCandidate {
		t.Fatalf("unexpected review list: %#v", reviews)
	}
	if err := service.Remove(ctx, updated.ReviewKey); err != nil {
		t.Fatal(err)
	}
	reviews, err = service.List(ctx, "test-device")
	if err != nil || len(reviews) != 0 {
		t.Fatalf("review was not removed: reviews=%#v err=%v", reviews, err)
	}
}

func TestServiceRejectsInvalidReviewMaterial(t *testing.T) {
	store, directory := reviewTestStore(t)
	defer store.Close()
	service, err := New(store, filepath.Join(directory, "browser-site-reviews.key"))
	if err != nil {
		t.Fatal(err)
	}
	cases := []ReviewInput{
		{ReviewKey: ReviewKey{DeviceID: "bad/device", BrowserID: "chrome", ProfileFingerprint: "abcdef0123456789abcdef01", Domain: "example.test"}, State: StateSignedInKeep},
		{ReviewKey: ReviewKey{DeviceID: "test-device", BrowserID: "firefox", ProfileFingerprint: "abcdef0123456789abcdef01", Domain: "example.test"}, State: StateSignedInKeep},
		{ReviewKey: ReviewKey{DeviceID: "test-device", BrowserID: "chrome", ProfileFingerprint: "raw-profile-path", Domain: "example.test"}, State: StateSignedInKeep},
		{ReviewKey: ReviewKey{DeviceID: "test-device", BrowserID: "chrome", ProfileFingerprint: "abcdef0123456789abcdef01", Domain: "https://example.test/path"}, State: StateSignedInKeep},
		{ReviewKey: ReviewKey{DeviceID: "test-device", BrowserID: "chrome", ProfileFingerprint: "abcdef0123456789abcdef01", Domain: "example.test"}, State: "protected-forever"},
	}
	for _, input := range cases {
		if _, err := service.Save(context.Background(), input, time.Now()); !errors.Is(err, ErrInvalidReview) {
			t.Fatalf("expected invalid review rejection for %#v, got %v", input, err)
		}
	}
}

func TestServiceKeepsDomainAndDecisionEncryptedAtRest(t *testing.T) {
	store, directory := reviewTestStore(t)
	keyPath := filepath.Join(directory, "browser-site-reviews.key")
	service, err := New(store, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Save(context.Background(), testReview(StateSignedInKeep), time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	paths, err := filepath.Glob(filepath.Join(directory, "haven.db*"))
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range paths {
		contents, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(contents, []byte("accounts.example.test")) || bytes.Contains(contents, []byte(StateSignedInKeep)) {
			t.Fatalf("private browser review material was stored in plaintext in %s", filepath.Base(path))
		}
	}
	key, err := os.ReadFile(keyPath)
	if err != nil || len(key) != 32 {
		t.Fatalf("unexpected browser review key: length=%d err=%v", len(key), err)
	}
}
