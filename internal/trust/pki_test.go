package trust

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestHubPKISignsBoundAgentIdentity(t *testing.T) {
	now := time.Date(2026, time.September, 1, 12, 0, 0, 0, time.UTC)
	directory := t.TempDir()
	pki, err := EnsureHubPKI(directory, now)
	if err != nil {
		t.Fatal(err)
	}
	agentIdentity, err := GenerateAgentIdentity("Test laptop")
	if err != nil {
		t.Fatal(err)
	}
	certificatePEM, certificate, err := pki.SignAgentCertificate(agentIdentity.CSRPEM, "dev_test", now, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	deviceID, err := DeviceIDFromCertificate(certificate)
	if err != nil || deviceID != "dev_test" {
		t.Fatalf("unexpected certificate identity %q: %v", deviceID, err)
	}
	if _, err := AgentTLSConfig(pki.CACertificatePEM, certificatePEM, agentIdentity.PrivateKeyPEM); err != nil {
		t.Fatal(err)
	}
	loaded, err := EnsureHubPKI(directory, now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if loaded.CACertificate.SerialNumber.Cmp(pki.CACertificate.SerialNumber) != 0 {
		t.Fatal("existing PKI identity was not preserved")
	}
}

func TestHubPKIRefusesPartialIdentity(t *testing.T) {
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, "ca.crt"), []byte("partial"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := EnsureHubPKI(directory, time.Now()); err == nil {
		t.Fatal("expected incomplete PKI to be rejected")
	}
}
