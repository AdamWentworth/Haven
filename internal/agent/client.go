package agent

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/AdamWentworth/haven/internal/fleet"
	"github.com/AdamWentworth/haven/internal/model"
	"github.com/AdamWentworth/haven/internal/sessionwatch"
	"github.com/AdamWentworth/haven/internal/storage"
	"github.com/AdamWentworth/haven/internal/trust"
)

const (
	maximumResponseBody   = 1 << 20
	maximumReportAttempts = 3
	reportRequestTimeout  = 10 * time.Second
)

var reportRetryDelays = [...]time.Duration{250 * time.Millisecond, time.Second}

type Config struct {
	HubURL      string `json:"hubUrl"`
	DeviceID    string `json:"deviceId"`
	DisplayName string `json:"displayName"`
	Sequence    int64  `json:"sequence"`
}

type Client struct {
	directory string
	config    Config
}

func DefaultDirectory() (string, error) {
	if configured := os.Getenv("HAVEN_AGENT_STATE_DIRECTORY"); configured != "" {
		return configured, nil
	}
	stateDirectory, err := storage.DefaultStateDirectory()
	if err != nil {
		return "", err
	}
	return filepath.Join(stateDirectory, "agent"), nil
}

func Enroll(ctx context.Context, directory, hubURL, displayName, token, caPath string) (Config, error) {
	if strings.TrimSpace(displayName) == "" || len(displayName) > 80 {
		return Config{}, errors.New("device name must contain 1 through 80 characters")
	}
	baseURL, err := validatedHubURL(hubURL)
	if err != nil {
		return Config{}, err
	}
	if !strings.HasPrefix(token, "enr_") {
		return Config{}, errors.New("enrollment token is invalid")
	}
	if _, err := os.Stat(filepath.Join(directory, "config.json")); err == nil {
		return Config{}, errors.New("this agent is already enrolled")
	} else if !errors.Is(err, os.ErrNotExist) {
		return Config{}, fmt.Errorf("inspect agent identity: %w", err)
	}
	caPEM, err := os.ReadFile(caPath)
	if err != nil {
		return Config{}, fmt.Errorf("read hub CA certificate: %w", err)
	}
	identity, err := trust.GenerateAgentIdentity(displayName)
	if err != nil {
		return Config{}, err
	}
	tlsConfig, err := trust.AgentTLSConfig(caPEM, nil, nil)
	if err != nil {
		return Config{}, err
	}
	requestBody, err := json.Marshal(model.EnrollmentRequest{Token: token, DisplayName: displayName, CSRPEM: string(identity.CSRPEM)})
	if err != nil {
		return Config{}, fmt.Errorf("encode enrollment request: %w", err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+"/v1/enroll", bytes.NewReader(requestBody))
	if err != nil {
		return Config{}, fmt.Errorf("create enrollment request: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	response, err := (&http.Client{Transport: &http.Transport{TLSClientConfig: tlsConfig}, Timeout: 15 * time.Second}).Do(request)
	if err != nil {
		return Config{}, fmt.Errorf("contact HAVEN hub: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusCreated {
		return Config{}, responseError(response)
	}
	var enrollment model.EnrollmentResponse
	if err := decodeResponse(response, &enrollment); err != nil {
		return Config{}, err
	}
	if enrollment.SchemaVersion != model.ObservationSchemaVersion || enrollment.DeviceID == "" {
		return Config{}, errors.New("hub returned an invalid enrollment identity")
	}
	if !sameCertificate(caPEM, []byte(enrollment.CACertificate)) {
		return Config{}, errors.New("hub returned a different CA certificate than the trusted enrollment CA")
	}
	if _, err := trust.AgentTLSConfig(caPEM, []byte(enrollment.CertificatePEM), identity.PrivateKeyPEM); err != nil {
		return Config{}, fmt.Errorf("validate enrolled identity: %w", err)
	}

	config := Config{HubURL: baseURL, DeviceID: enrollment.DeviceID, DisplayName: strings.TrimSpace(displayName)}
	if err := saveIdentity(directory, config, caPEM, []byte(enrollment.CertificatePEM), identity.PrivateKeyPEM); err != nil {
		return Config{}, err
	}
	return config, nil
}

func Load(directory string) (*Client, error) {
	contents, err := os.ReadFile(filepath.Join(directory, "config.json"))
	if err != nil {
		return nil, fmt.Errorf("read agent configuration: %w", err)
	}
	var config Config
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&config); err != nil {
		return nil, fmt.Errorf("decode agent configuration: %w", err)
	}
	if config.DeviceID == "" {
		return nil, errors.New("agent configuration has no device identity")
	}
	if _, err := validatedHubURL(config.HubURL); err != nil {
		return nil, err
	}
	return &Client{directory: directory, config: config}, nil
}

func (client *Client) Config() Config {
	return client.config
}

func (client *Client) Report(ctx context.Context, snapshot model.SecuritySnapshot, installation ...string) (model.ObservationReceipt, error) {
	changes, baselineUpdate, baselineErr := sessionwatch.Prepare(client.directory, snapshot.BrowserSecurity)
	if snapshot.BrowserSecurity != nil {
		snapshot.BrowserSecurity.Changes = changes
	}
	if baselineErr != nil {
		snapshot.Notices = append(snapshot.Notices, model.CollectorNotice{Source: "Browser change watch", Severity: "information", Message: "The local browser baseline could not be verified; HAVEN established a new baseline without inferring a change."})
	}
	caPEM, err := os.ReadFile(filepath.Join(client.directory, "ca.crt"))
	if err != nil {
		return model.ObservationReceipt{}, fmt.Errorf("read agent CA certificate: %w", err)
	}
	certificatePEM, err := os.ReadFile(filepath.Join(client.directory, "client.crt"))
	if err != nil {
		return model.ObservationReceipt{}, fmt.Errorf("read agent certificate: %w", err)
	}
	privateKeyPEM, err := os.ReadFile(filepath.Join(client.directory, "client.key"))
	if err != nil {
		return model.ObservationReceipt{}, fmt.Errorf("read agent private key: %w", err)
	}
	tlsConfig, err := trust.AgentTLSConfig(caPEM, certificatePEM, privateKeyPEM)
	if err != nil {
		return model.ObservationReceipt{}, err
	}

	client.config.Sequence++
	if err := writeConfig(client.directory, client.config); err != nil {
		return model.ObservationReceipt{}, err
	}
	snapshot.Device.DeviceID = client.config.DeviceID
	observationID, err := randomObservationID()
	if err != nil {
		return model.ObservationReceipt{}, err
	}
	installationKind := "interactive"
	if len(installation) > 0 {
		installationKind = installation[0]
	}
	metadata := fleet.MetadataForSnapshot(snapshot, installationKind)
	envelope := model.ObservationEnvelope{SchemaVersion: model.ObservationSchemaVersion, ObservationID: observationID, DeviceID: client.config.DeviceID, Sequence: client.config.Sequence, SentAt: time.Now().UTC(), Agent: &metadata, Snapshot: snapshot}
	payload, err := json.Marshal(envelope)
	if err != nil {
		return model.ObservationReceipt{}, fmt.Errorf("encode observation: %w", err)
	}
	httpClient := &http.Client{Transport: &http.Transport{TLSClientConfig: tlsConfig}, Timeout: reportRequestTimeout}
	var lastError error
	for attempt := 0; attempt < maximumReportAttempts; attempt++ {
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, client.config.HubURL+"/v1/observations", bytes.NewReader(payload))
		if err != nil {
			return model.ObservationReceipt{}, fmt.Errorf("create observation request: %w", err)
		}
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Accept", "application/json")
		response, err := httpClient.Do(request)
		if err != nil {
			lastError = fmt.Errorf("report observation: %w", err)
		} else if response.StatusCode == http.StatusAccepted {
			var receipt model.ObservationReceipt
			decodeErr := decodeResponse(response, &receipt)
			response.Body.Close()
			if decodeErr != nil {
				return model.ObservationReceipt{}, decodeErr
			}
			if receipt.ObservationID != envelope.ObservationID || receipt.AcceptedAt.IsZero() {
				return model.ObservationReceipt{}, errors.New("hub returned an invalid observation receipt")
			}
			if err := baselineUpdate.Commit(); err != nil {
				return model.ObservationReceipt{}, err
			}
			return receipt, nil
		} else if retryableReportStatus(response.StatusCode) {
			lastError = responseError(response)
			response.Body.Close()
		} else {
			requestError := responseError(response)
			response.Body.Close()
			return model.ObservationReceipt{}, requestError
		}

		if attempt < len(reportRetryDelays) {
			if err := waitForReportRetry(ctx, reportRetryDelays[attempt]); err != nil {
				return model.ObservationReceipt{}, err
			}
		}
	}
	return model.ObservationReceipt{}, lastError
}

func retryableReportStatus(status int) bool {
	return status == http.StatusTooManyRequests || status >= http.StatusInternalServerError
}

func waitForReportRetry(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return fmt.Errorf("report observation: %w", ctx.Err())
	case <-timer.C:
		return nil
	}
}

func validatedHubURL(value string) (string, error) {
	parsed, err := url.Parse(strings.TrimRight(value, "/"))
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || (parsed.Path != "" && parsed.Path != "/") {
		return "", errors.New("hub URL must be an HTTPS origin such as https://localhost:5443")
	}
	return parsed.Scheme + "://" + parsed.Host, nil
}

func saveIdentity(directory string, config Config, caPEM, certificatePEM, privateKeyPEM []byte) error {
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return fmt.Errorf("create agent state directory: %w", err)
	}
	for _, file := range []struct {
		name       string
		contents   []byte
		permission os.FileMode
	}{{"ca.crt", caPEM, 0o600}, {"client.crt", certificatePEM, 0o600}, {"client.key", privateKeyPEM, 0o600}} {
		path := filepath.Join(directory, file.name)
		if err := os.WriteFile(path, file.contents, file.permission); err != nil {
			return fmt.Errorf("save agent identity %s: %w", file.name, err)
		}
		if err := os.Chmod(path, file.permission); err != nil {
			return fmt.Errorf("protect agent identity %s: %w", file.name, err)
		}
	}
	return writeConfig(directory, config)
}

func writeConfig(directory string, config Config) error {
	contents, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("encode agent configuration: %w", err)
	}
	temporary, err := os.CreateTemp(directory, ".config-*.tmp")
	if err != nil {
		return fmt.Errorf("create agent configuration: %w", err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("protect agent configuration: %w", err)
	}
	if _, err := temporary.Write(contents); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("write agent configuration: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("sync agent configuration: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close agent configuration: %w", err)
	}
	if err := os.Rename(temporaryPath, filepath.Join(directory, "config.json")); err != nil {
		return fmt.Errorf("replace agent configuration: %w", err)
	}
	return nil
}

func responseError(response *http.Response) error {
	var apiError model.APIError
	if err := decodeResponse(response, &apiError); err == nil && apiError.Message != "" {
		return fmt.Errorf("hub rejected request (HTTP %d, %s): %s", response.StatusCode, apiError.Code, apiError.Message)
	}
	return fmt.Errorf("hub rejected request with HTTP %d", response.StatusCode)
}

func decodeResponse(response *http.Response, destination any) error {
	decoder := json.NewDecoder(io.LimitReader(response.Body, maximumResponseBody))
	if err := decoder.Decode(destination); err != nil {
		return fmt.Errorf("decode hub response: %w", err)
	}
	return nil
}

func sameCertificate(leftPEM, rightPEM []byte) bool {
	leftPool := x509.NewCertPool()
	rightPool := x509.NewCertPool()
	if !leftPool.AppendCertsFromPEM(leftPEM) || !rightPool.AppendCertsFromPEM(rightPEM) {
		return false
	}
	return leftPool.Equal(rightPool)
}

func randomObservationID() (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", fmt.Errorf("generate observation identity: %w", err)
	}
	return "obs_" + hex.EncodeToString(value), nil
}
