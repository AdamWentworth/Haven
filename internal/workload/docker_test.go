package workload

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/AdamWentworth/haven/internal/model"
)

type doerFunc func(*http.Request) (*http.Response, error)

func (function doerFunc) Do(request *http.Request) (*http.Response, error) { return function(request) }

func TestCollectDockerRetainsOnlyAttributionFields(t *testing.T) {
	payload := `[{"Id":"secret-id","Names":["/example_api"],"Image":"ghcr.io/example/api:sha-123","Command":"contains secrets","State":"running","Status":"Up 4 hours (healthy)","Ports":[{"IP":"192.0.2.77","PrivatePort":4000,"PublicPort":4000,"Type":"tcp"},{"PrivatePort":9090,"PublicPort":0,"Type":"tcp"}],"Labels":{"com.docker.compose.project":"example","com.docker.compose.service":"api","private.secret":"must-not-survive"},"Mounts":[{"Source":"/private"}]}]`
	client := doerFunc(func(request *http.Request) (*http.Response, error) {
		if request.Method != http.MethodGet || request.URL.Path != "/containers/json" || request.URL.Query().Get("all") != "false" {
			t.Fatalf("unexpected Docker request: %s %s", request.Method, request.URL.String())
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(payload))}, nil
	})
	collectedAt := time.Date(2026, time.September, 2, 12, 0, 0, 0, time.UTC)
	inventory, err := collectDocker(context.Background(), client, collectedAt)
	if err != nil {
		t.Fatal(err)
	}
	if inventory.Runtime != "docker" || !inventory.CollectedAt.Equal(collectedAt) || len(inventory.Workloads) != 1 {
		t.Fatalf("unexpected inventory: %#v", inventory)
	}
	container := inventory.Workloads[0]
	if container.Name != "example_api" || container.Project != "example" || container.Service != "api" || container.Health != "healthy" || len(container.Ports) != 2 {
		t.Fatalf("unexpected sanitized container: %#v", container)
	}
	if !container.Ports[0].Published || container.Ports[0].HostAddress != "192.0.2.77" || container.Ports[0].HostPort != 4000 || container.Ports[1].Published {
		t.Fatalf("unexpected sanitized ports: %#v", container.Ports)
	}
}

func TestWorkloadInventoryFileRoundTripAndValidation(t *testing.T) {
	path := t.TempDir() + "/inventory.json"
	inventory := model.WorkloadInventory{
		Runtime: "docker", CollectedAt: time.Now().UTC(),
		Workloads: []model.ContainerWorkload{{
			Name: "haven_proxy", Image: "caddy:2.10", Project: "haven", Service: "proxy", State: "running", Health: "healthy",
			Ports: []model.ContainerPortBinding{{Protocol: "TCP", ContainerPort: 443, Published: true, HostAddress: "::", HostPort: 8443}},
		}},
	}
	if err := WriteFile(path, inventory); err != nil {
		t.Fatal(err)
	}
	loaded, err := ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.Workloads) != 1 || loaded.Workloads[0].Name != "haven_proxy" || loaded.Workloads[0].Ports[0].HostPort != 8443 {
		t.Fatalf("unexpected round-trip inventory: %#v", loaded)
	}

	loaded.Workloads[0].Ports[0].HostPort = 0
	if err := WriteFile(path, loaded); err == nil {
		t.Fatal("an invalid published port must be rejected")
	}
}

func TestCollectDockerRejectsFailedEngineQuery(t *testing.T) {
	client := doerFunc(func(*http.Request) (*http.Response, error) { return nil, errors.New("denied") })
	if _, err := collectDocker(context.Background(), client, time.Now()); err == nil || !strings.Contains(err.Error(), "query Docker inventory") {
		t.Fatalf("expected a bounded query error, got %v", err)
	}
}
