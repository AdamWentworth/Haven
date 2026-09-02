package trust

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const deviceURIPrefix = "spiffe://haven.local/device/"

type HubPKI struct {
	CACertificate     *x509.Certificate
	CAKey             *ecdsa.PrivateKey
	CACertificatePEM  []byte
	ServerCertificate tls.Certificate
}

type AgentIdentity struct {
	PrivateKeyPEM []byte
	CSRPEM        []byte
}

func EnsureHubPKI(directory string, now time.Time) (*HubPKI, error) {
	return EnsureHubPKIForServerNames(directory, now, nil)
}

// EnsureHubPKIForServerNames creates or loads the private authority used by
// native agents. Additional names are included in the agent endpoint's server
// certificate so a remote agent can verify the production hub by its stable
// private hostname or address.
func EnsureHubPKIForServerNames(directory string, now time.Time, serverNames []string) (*HubPKI, error) {
	serverNames, err := normalizeServerNames(serverNames)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return nil, fmt.Errorf("create HAVEN PKI directory: %w", err)
	}

	paths := hubPKIPaths(directory)
	existing := 0
	for _, path := range paths {
		if _, err := os.Stat(path); err == nil {
			existing++
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("inspect HAVEN PKI: %w", err)
		}
	}

	if existing == 0 {
		if err := generateHubPKI(paths, now, serverNames); err != nil {
			return nil, err
		}
	} else if existing != len(paths) {
		return nil, errors.New("HAVEN PKI is incomplete; refusing to regenerate or overwrite identity files")
	}

	pki, err := loadHubPKI(paths)
	if err != nil {
		return nil, err
	}
	if len(pki.ServerCertificate.Certificate) == 0 {
		return nil, errors.New("HAVEN agent endpoint certificate is missing")
	}
	serverCertificate, err := x509.ParseCertificate(pki.ServerCertificate.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("parse HAVEN agent endpoint certificate: %w", err)
	}
	for _, name := range serverNames {
		if err := serverCertificate.VerifyHostname(name); err != nil {
			return nil, fmt.Errorf("HAVEN agent endpoint certificate does not include %q; preserve the existing PKI or rotate it before enrolling agents: %w", name, err)
		}
	}
	return pki, nil
}

func GenerateAgentIdentity(displayName string) (AgentIdentity, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return AgentIdentity{}, fmt.Errorf("generate agent private key: %w", err)
	}
	requestDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: strings.TrimSpace(displayName)},
	}, privateKey)
	if err != nil {
		return AgentIdentity{}, fmt.Errorf("create agent certificate request: %w", err)
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return AgentIdentity{}, fmt.Errorf("encode agent private key: %w", err)
	}
	return AgentIdentity{
		PrivateKeyPEM: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER}),
		CSRPEM:        pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: requestDER}),
	}, nil
}

func (pki *HubPKI) SignAgentCertificate(
	csrPEM []byte,
	deviceID string,
	now time.Time,
	validFor time.Duration,
) ([]byte, *x509.Certificate, error) {
	block, _ := pem.Decode(csrPEM)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, nil, errors.New("certificate request is not valid PEM")
	}
	request, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse certificate request: %w", err)
	}
	if err := request.CheckSignature(); err != nil {
		return nil, nil, fmt.Errorf("verify certificate request: %w", err)
	}
	publicKey, ok := request.PublicKey.(*ecdsa.PublicKey)
	if !ok || publicKey.Curve != elliptic.P256() {
		return nil, nil, errors.New("agent keys must use ECDSA P-256")
	}
	identityURI, err := url.Parse(deviceURIPrefix + deviceID)
	if err != nil {
		return nil, nil, fmt.Errorf("create agent identity URI: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, nil, err
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "HAVEN device " + deviceID},
		NotBefore:    now.Add(-5 * time.Minute),
		NotAfter:     now.Add(validFor),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		URIs:         []*url.URL{identityURI},
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, pki.CACertificate, publicKey, pki.CAKey)
	if err != nil {
		return nil, nil, fmt.Errorf("sign agent certificate: %w", err)
	}
	certificate, err := x509.ParseCertificate(certificateDER)
	if err != nil {
		return nil, nil, fmt.Errorf("parse signed agent certificate: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER}), certificate, nil
}

func ServerTLSConfig(pki *HubPKI) *tls.Config {
	pool := x509.NewCertPool()
	pool.AddCert(pki.CACertificate)
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{pki.ServerCertificate},
		ClientAuth:   tls.VerifyClientCertIfGiven,
		ClientCAs:    pool,
	}
}

func AgentTLSConfig(caPEM, certificatePEM, privateKeyPEM []byte) (*tls.Config, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("agent CA certificate is invalid")
	}
	config := &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool}
	if len(certificatePEM) > 0 || len(privateKeyPEM) > 0 {
		certificate, err := tls.X509KeyPair(certificatePEM, privateKeyPEM)
		if err != nil {
			return nil, fmt.Errorf("load agent certificate: %w", err)
		}
		config.Certificates = []tls.Certificate{certificate}
	}
	return config, nil
}

func DeviceIDFromCertificate(certificate *x509.Certificate) (string, error) {
	for _, identity := range certificate.URIs {
		value := identity.String()
		if strings.HasPrefix(value, deviceURIPrefix) {
			deviceID := strings.TrimPrefix(value, deviceURIPrefix)
			if deviceID != "" && !strings.ContainsAny(deviceID, "/?#") {
				return deviceID, nil
			}
		}
	}
	return "", errors.New("client certificate has no HAVEN device identity")
}

func CertificateSerial(certificate *x509.Certificate) string {
	return certificate.SerialNumber.Text(16)
}

func NewDeviceID() (string, error) {
	value, err := randomBytes(16)
	if err != nil {
		return "", fmt.Errorf("generate device identity: %w", err)
	}
	return "dev_" + hex.EncodeToString(value), nil
}

func NewEnrollmentToken() (string, []byte, error) {
	value, err := randomBytes(32)
	if err != nil {
		return "", nil, fmt.Errorf("generate enrollment token: %w", err)
	}
	token := "enr_" + base64.RawURLEncoding.EncodeToString(value)
	return token, HashEnrollmentToken(token), nil
}

func HashEnrollmentToken(token string) []byte {
	digest := sha256.Sum256([]byte(token))
	return digest[:]
}

func generateHubPKI(paths []string, now time.Time, serverNames []string) error {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate HAVEN authority key: %w", err)
	}
	caSerial, err := randomSerial()
	if err != nil {
		return err
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          caSerial,
		Subject:               pkix.Name{CommonName: "HAVEN Local Device Authority"},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return fmt.Errorf("create HAVEN authority certificate: %w", err)
	}
	caCertificate, err := x509.ParseCertificate(caDER)
	if err != nil {
		return fmt.Errorf("parse HAVEN authority certificate: %w", err)
	}

	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate HAVEN server key: %w", err)
	}
	serverSerial, err := randomSerial()
	if err != nil {
		return err
	}
	dnsNames := []string{"localhost"}
	ipAddresses := []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}
	for _, name := range serverNames {
		if address := net.ParseIP(name); address != nil {
			ipAddresses = append(ipAddresses, address)
		} else {
			dnsNames = append(dnsNames, name)
		}
	}
	serverTemplate := &x509.Certificate{
		SerialNumber: serverSerial,
		Subject:      pkix.Name{CommonName: "HAVEN local agent endpoint"},
		NotBefore:    now.Add(-5 * time.Minute),
		NotAfter:     now.AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     dnsNames,
		IPAddresses:  ipAddresses,
	}
	serverDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, caCertificate, &serverKey.PublicKey, caKey)
	if err != nil {
		return fmt.Errorf("create HAVEN server certificate: %w", err)
	}

	caKeyDER, err := x509.MarshalPKCS8PrivateKey(caKey)
	if err != nil {
		return fmt.Errorf("encode HAVEN authority key: %w", err)
	}
	serverKeyDER, err := x509.MarshalPKCS8PrivateKey(serverKey)
	if err != nil {
		return fmt.Errorf("encode HAVEN server key: %w", err)
	}
	contents := [][]byte{
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: caKeyDER}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverDER}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: serverKeyDER}),
	}
	permissions := []os.FileMode{0o644, 0o600, 0o644, 0o600}
	for index, path := range paths {
		if err := writeNewFile(path, contents[index], permissions[index]); err != nil {
			return err
		}
	}
	return nil
}

func normalizeServerNames(values []string) ([]string, error) {
	seen := map[string]bool{"localhost": true, "127.0.0.1": true, "::1": true}
	names := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			continue
		}
		if len(value) > 253 || strings.ContainsAny(value, " /\\?#@") {
			return nil, fmt.Errorf("invalid HAVEN agent server name %q", value)
		}
		if net.ParseIP(value) == nil {
			candidate := &x509.Certificate{DNSNames: []string{value}}
			if err := candidate.VerifyHostname(value); err != nil {
				return nil, fmt.Errorf("invalid HAVEN agent server name %q: %w", value, err)
			}
		}
		seen[value] = true
		names = append(names, value)
	}
	return names, nil
}

func loadHubPKI(paths []string) (*HubPKI, error) {
	caPEM, err := os.ReadFile(paths[0])
	if err != nil {
		return nil, fmt.Errorf("read HAVEN authority certificate: %w", err)
	}
	caBlock, _ := pem.Decode(caPEM)
	if caBlock == nil || caBlock.Type != "CERTIFICATE" {
		return nil, errors.New("HAVEN authority certificate is invalid")
	}
	caCertificate, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse HAVEN authority certificate: %w", err)
	}
	caKeyPEM, err := os.ReadFile(paths[1])
	if err != nil {
		return nil, fmt.Errorf("read HAVEN authority key: %w", err)
	}
	caKey, err := parseECPrivateKey(caKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("parse HAVEN authority key: %w", err)
	}
	serverCertificate, err := tls.LoadX509KeyPair(paths[2], paths[3])
	if err != nil {
		return nil, fmt.Errorf("load HAVEN server certificate: %w", err)
	}
	return &HubPKI{
		CACertificate:     caCertificate,
		CAKey:             caKey,
		CACertificatePEM:  caPEM,
		ServerCertificate: serverCertificate,
	}, nil
}

func parseECPrivateKey(contents []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(contents)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, errors.New("private key is not valid PKCS#8 PEM")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	ecKey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("private key is not ECDSA")
	}
	return ecKey, nil
}

func hubPKIPaths(directory string) []string {
	return []string{
		filepath.Join(directory, "ca.crt"),
		filepath.Join(directory, "ca.key"),
		filepath.Join(directory, "server.crt"),
		filepath.Join(directory, "server.key"),
	}
}

func writeNewFile(path string, contents []byte, permission os.FileMode) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, permission)
	if err != nil {
		return fmt.Errorf("create PKI file %s: %w", filepath.Base(path), err)
	}
	if _, err := file.Write(contents); err != nil {
		_ = file.Close()
		return fmt.Errorf("write PKI file %s: %w", filepath.Base(path), err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return fmt.Errorf("sync PKI file %s: %w", filepath.Base(path), err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close PKI file %s: %w", filepath.Base(path), err)
	}
	return nil
}

func randomSerial() (*big.Int, error) {
	value, err := randomBytes(16)
	if err != nil {
		return nil, fmt.Errorf("generate certificate serial: %w", err)
	}
	serial := new(big.Int).SetBytes(value)
	if serial.Sign() == 0 {
		serial.SetInt64(1)
	}
	return serial, nil
}

func randomBytes(size int) ([]byte, error) {
	value := make([]byte, size)
	if _, err := rand.Read(value); err != nil {
		return nil, err
	}
	return value, nil
}
