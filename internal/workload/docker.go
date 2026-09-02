package workload

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/AdamWentworth/haven/internal/model"
)

const (
	maximumDockerResponse = 2 << 20
	maximumInventoryFile  = 1 << 20
	maximumWorkloads      = 256
	maximumPorts          = 2048
)

type dockerContainer struct {
	Names  []string          `json:"Names"`
	Image  string            `json:"Image"`
	State  string            `json:"State"`
	Status string            `json:"Status"`
	Ports  []dockerPort      `json:"Ports"`
	Labels map[string]string `json:"Labels"`
}

type dockerPort struct {
	IP          string `json:"IP"`
	PrivatePort int    `json:"PrivatePort"`
	PublicPort  int    `json:"PublicPort"`
	Type        string `json:"Type"`
}

type httpDoer interface {
	Do(*http.Request) (*http.Response, error)
}

func CollectDocker(ctx context.Context, socketPath string) (model.WorkloadInventory, error) {
	socketPath = strings.TrimSpace(socketPath)
	if socketPath == "" || !filepath.IsAbs(socketPath) {
		return model.WorkloadInventory{}, errors.New("Docker socket path must be absolute")
	}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "unix", socketPath)
		},
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 8 * time.Second}
	return collectDocker(ctx, client, time.Now().UTC())
}

func collectDocker(ctx context.Context, client httpDoer, collectedAt time.Time) (model.WorkloadInventory, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://docker/containers/json?all=false", nil)
	if err != nil {
		return model.WorkloadInventory{}, fmt.Errorf("create Docker inventory request: %w", err)
	}
	response, err := client.Do(request)
	if err != nil {
		return model.WorkloadInventory{}, fmt.Errorf("query Docker inventory: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return model.WorkloadInventory{}, fmt.Errorf("query Docker inventory: HTTP %d", response.StatusCode)
	}
	payload, err := io.ReadAll(io.LimitReader(response.Body, maximumDockerResponse+1))
	if err != nil {
		return model.WorkloadInventory{}, fmt.Errorf("read Docker inventory: %w", err)
	}
	if len(payload) > maximumDockerResponse {
		return model.WorkloadInventory{}, errors.New("Docker inventory response exceeds the safety limit")
	}
	containers := []dockerContainer{}
	if err := json.Unmarshal(payload, &containers); err != nil {
		return model.WorkloadInventory{}, fmt.Errorf("decode Docker inventory: %w", err)
	}
	if len(containers) > maximumWorkloads {
		return model.WorkloadInventory{}, errors.New("Docker inventory contains too many workloads")
	}
	inventory := model.WorkloadInventory{Runtime: "docker", CollectedAt: collectedAt.UTC(), Workloads: []model.ContainerWorkload{}}
	totalPorts := 0
	for _, container := range containers {
		workload, ok := sanitizeContainer(container)
		if !ok {
			continue
		}
		totalPorts += len(workload.Ports)
		if totalPorts > maximumPorts {
			return model.WorkloadInventory{}, errors.New("Docker inventory contains too many ports")
		}
		inventory.Workloads = append(inventory.Workloads, workload)
	}
	sort.Slice(inventory.Workloads, func(left, right int) bool {
		return inventory.Workloads[left].Name < inventory.Workloads[right].Name
	})
	return inventory, nil
}

func sanitizeContainer(container dockerContainer) (model.ContainerWorkload, bool) {
	name := ""
	for _, candidate := range container.Names {
		candidate = strings.TrimPrefix(strings.TrimSpace(candidate), "/")
		if name = safeIdentifier(candidate, 128, "_.-"); name != "" {
			break
		}
	}
	if name == "" {
		return model.ContainerWorkload{}, false
	}
	workload := model.ContainerWorkload{
		Name:    name,
		Image:   safeIdentifier(container.Image, 240, "._/@:-"),
		Project: safeIdentifier(container.Labels["com.docker.compose.project"], 128, "_.-"),
		Service: safeIdentifier(container.Labels["com.docker.compose.service"], 128, "_.-"),
		State:   safeIdentifier(strings.ToLower(container.State), 32, "_-"),
		Health:  dockerHealth(container.Status),
		Ports:   []model.ContainerPortBinding{},
	}
	if workload.State != "running" {
		return model.ContainerWorkload{}, false
	}
	for _, port := range container.Ports {
		protocol := strings.ToUpper(strings.TrimSpace(port.Type))
		if (protocol != "TCP" && protocol != "UDP") || port.PrivatePort < 1 || port.PrivatePort > 65535 || port.PublicPort < 0 || port.PublicPort > 65535 {
			continue
		}
		binding := model.ContainerPortBinding{Protocol: protocol, ContainerPort: port.PrivatePort, Published: port.PublicPort > 0}
		if binding.Published {
			binding.HostPort = port.PublicPort
			binding.HostAddress = normalizedAddress(port.IP)
		}
		workload.Ports = append(workload.Ports, binding)
	}
	sort.Slice(workload.Ports, func(left, right int) bool {
		if workload.Ports[left].Published != workload.Ports[right].Published {
			return workload.Ports[left].Published
		}
		if workload.Ports[left].HostPort != workload.Ports[right].HostPort {
			return workload.Ports[left].HostPort < workload.Ports[right].HostPort
		}
		if workload.Ports[left].ContainerPort != workload.Ports[right].ContainerPort {
			return workload.Ports[left].ContainerPort < workload.Ports[right].ContainerPort
		}
		return workload.Ports[left].HostAddress < workload.Ports[right].HostAddress
	})
	return workload, true
}

func safeIdentifier(value string, maximum int, punctuation string) string {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > maximum {
		return ""
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9') || strings.ContainsRune(punctuation, character) {
			continue
		}
		return ""
	}
	return value
}

func normalizedAddress(value string) string {
	value = strings.Trim(strings.TrimSpace(value), "[]")
	if value == "" {
		return ""
	}
	if address := net.ParseIP(value); address != nil {
		return address.String()
	}
	return ""
}

func dockerHealth(status string) string {
	status = strings.ToLower(status)
	for _, health := range []string{"unhealthy", "healthy", "starting"} {
		if strings.Contains(status, "("+health+")") {
			return health
		}
	}
	return "not-configured"
}

func WriteFile(path string, inventory model.WorkloadInventory) error {
	path = strings.TrimSpace(path)
	if path == "" || !filepath.IsAbs(path) {
		return errors.New("workload inventory path must be absolute")
	}
	if err := validateInventory(inventory); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create workload inventory directory: %w", err)
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".workload-inventory-*")
	if err != nil {
		return fmt.Errorf("create workload inventory: %w", err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return fmt.Errorf("protect workload inventory: %w", err)
	}
	encoder := json.NewEncoder(temporary)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(inventory); err != nil {
		temporary.Close()
		return fmt.Errorf("encode workload inventory: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return fmt.Errorf("sync workload inventory: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close workload inventory: %w", err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("publish workload inventory: %w", err)
	}
	return nil
}

func ReadFile(path string) (model.WorkloadInventory, error) {
	path = strings.TrimSpace(path)
	if path == "" || !filepath.IsAbs(path) {
		return model.WorkloadInventory{}, errors.New("workload inventory path must be absolute")
	}
	file, err := os.Open(path)
	if err != nil {
		return model.WorkloadInventory{}, err
	}
	defer file.Close()
	payload, err := io.ReadAll(io.LimitReader(file, maximumInventoryFile+1))
	if err != nil {
		return model.WorkloadInventory{}, fmt.Errorf("read workload inventory: %w", err)
	}
	if len(payload) > maximumInventoryFile {
		return model.WorkloadInventory{}, errors.New("workload inventory exceeds the safety limit")
	}
	inventory := model.WorkloadInventory{}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&inventory); err != nil {
		return model.WorkloadInventory{}, fmt.Errorf("decode workload inventory: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return model.WorkloadInventory{}, errors.New("workload inventory contains trailing data")
	}
	if err := validateInventory(inventory); err != nil {
		return model.WorkloadInventory{}, err
	}
	return inventory, nil
}

func validateInventory(inventory model.WorkloadInventory) error {
	if inventory.Runtime != "docker" || inventory.CollectedAt.IsZero() || len(inventory.Workloads) > maximumWorkloads {
		return errors.New("workload inventory is invalid")
	}
	totalPorts := 0
	for _, container := range inventory.Workloads {
		if container.Name == "" || safeIdentifier(container.Name, 128, "_.-") != container.Name ||
			safeIdentifier(container.Image, 240, "._/@:-") != container.Image ||
			safeIdentifier(container.Project, 128, "_.-") != container.Project ||
			safeIdentifier(container.Service, 128, "_.-") != container.Service ||
			container.State != "running" {
			return errors.New("workload inventory contains an invalid container")
		}
		if container.Health != "healthy" && container.Health != "unhealthy" && container.Health != "starting" && container.Health != "not-configured" {
			return errors.New("workload inventory contains an invalid health state")
		}
		totalPorts += len(container.Ports)
		if totalPorts > maximumPorts {
			return errors.New("workload inventory contains too many ports")
		}
		for _, port := range container.Ports {
			if (port.Protocol != "TCP" && port.Protocol != "UDP") || port.ContainerPort < 1 || port.ContainerPort > 65535 {
				return errors.New("workload inventory contains an invalid container port")
			}
			if port.Published {
				if port.HostPort < 1 || port.HostPort > 65535 || (port.HostAddress != "" && normalizedAddress(port.HostAddress) != port.HostAddress) {
					return errors.New("workload inventory contains an invalid published port")
				}
			} else if port.HostPort != 0 || port.HostAddress != "" {
				return errors.New("workload inventory contains host data for an unpublished port")
			}
		}
	}
	return nil
}
