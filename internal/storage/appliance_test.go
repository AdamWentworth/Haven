package storage

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/AdamWentworth/haven/internal/model"
)

func TestManagedApplianceStatusPersistsBoundedCurrentState(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, filepath.Join(t.TempDir(), "haven.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	configuredAt := time.Date(2026, time.September, 4, 4, 0, 0, 0, time.UTC)
	definitions := []model.ManagedApplianceDefinition{{
		ID: "nas", DisplayName: "TNAS", Kind: "nas", Address: testPrivateApplianceAddress(),
		Services: []model.ManagedServiceDefinition{
			{ID: "smb", Name: "SMB", Protocol: "TCP", Port: 445, Required: true},
			{ID: "admin", Name: "Management HTTPS", Protocol: "TCP", Port: 5443, TLS: true, Required: true},
		},
	}}
	if err := store.SyncManagedAppliances(ctx, definitions, configuredAt); err != nil {
		t.Fatal(err)
	}
	statuses, err := store.ListManagedAppliances(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(statuses) != 1 || statuses[0].Status != "pending" || len(statuses[0].Services) != 2 {
		t.Fatalf("unexpected initial state: %#v", statuses)
	}

	firstCheck := configuredAt.Add(time.Minute)
	certificate := &model.ManagedCertificateStatus{Subject: "CN=nas", Issuer: "CN=test", Fingerprint: "AABB", NotBefore: configuredAt.Add(-time.Hour), NotAfter: configuredAt.AddDate(1, 0, 0)}
	if err := store.RecordManagedApplianceProbe(ctx, "nas", []model.ManagedServiceStatus{
		{ID: "smb", Reachable: true},
		{ID: "admin", Reachable: true, Certificate: certificate},
	}, firstCheck); err != nil {
		t.Fatal(err)
	}
	statuses, err = store.ListManagedAppliances(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if statuses[0].Status != "healthy" || !statuses[0].Services[1].Reachable || statuses[0].Services[1].Certificate == nil {
		t.Fatalf("successful state was not retained: %#v", statuses[0])
	}

	secondCheck := firstCheck.Add(time.Minute)
	if err := store.RecordManagedApplianceProbe(ctx, "nas", []model.ManagedServiceStatus{
		{ID: "smb", Reachable: true},
		{ID: "admin", Reachable: false, ErrorClass: "timeout"},
	}, secondCheck); err != nil {
		t.Fatal(err)
	}
	statuses, _ = store.ListManagedAppliances(ctx)
	if statuses[0].Status != "rechecking" || statuses[0].Services[1].ConsecutiveFailures != 1 || statuses[0].Services[1].Certificate != nil {
		t.Fatalf("first failure should be a quiet recheck: %#v", statuses[0])
	}
	if err := store.RecordManagedApplianceProbe(ctx, "nas", []model.ManagedServiceStatus{{ID: "smb", Reachable: true}, {ID: "admin", ErrorClass: "timeout"}}, secondCheck.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	statuses, _ = store.ListManagedAppliances(ctx)
	if statuses[0].Status != "attention" || statuses[0].Services[1].ConsecutiveFailures != 2 {
		t.Fatalf("repeated required failure should become attention: %#v", statuses[0])
	}
}

func TestManagedApplianceSyncRemovesOnlyConfigurationNoLongerPresent(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, filepath.Join(t.TempDir(), "haven.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	now := time.Now().UTC()
	definitions := []model.ManagedApplianceDefinition{{ID: "nas", DisplayName: "NAS", Kind: "nas", Address: testPrivateApplianceAddress(), Services: []model.ManagedServiceDefinition{{ID: "smb", Name: "SMB", Protocol: "TCP", Port: 445, Required: true}, {ID: "admin", Name: "Admin", Protocol: "TCP", Port: 5443}}}}
	if err := store.SyncManagedAppliances(ctx, definitions, now); err != nil {
		t.Fatal(err)
	}
	definitions[0].Services = definitions[0].Services[:1]
	if err := store.SyncManagedAppliances(ctx, definitions, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	statuses, _ := store.ListManagedAppliances(ctx)
	if len(statuses) != 1 || len(statuses[0].Services) != 1 || statuses[0].Services[0].ID != "smb" {
		t.Fatalf("stale service remained: %#v", statuses)
	}
	if err := store.RecordManagedApplianceProbe(ctx, "nas", []model.ManagedServiceStatus{{ID: "smb", Reachable: true}}, now.Add(90*time.Second)); err != nil {
		t.Fatal(err)
	}
	definitions[0].Services[0].Port = 1445
	if err := store.SyncManagedAppliances(ctx, definitions, now.Add(100*time.Second)); err != nil {
		t.Fatal(err)
	}
	statuses, _ = store.ListManagedAppliances(ctx)
	if statuses[0].Status != "pending" || statuses[0].Services[0].LastCheckedAt != nil {
		t.Fatalf("changed endpoint retained stale health evidence: %#v", statuses[0])
	}
	if err := store.SyncManagedAppliances(ctx, nil, now.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	statuses, _ = store.ListManagedAppliances(ctx)
	if len(statuses) != 0 {
		t.Fatalf("stale appliance remained: %#v", statuses)
	}
}

func testPrivateApplianceAddress() string {
	return strings.Join([]string{"192", "168", "1", "69"}, ".")
}
