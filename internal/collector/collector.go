package collector

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"time"

	"github.com/AdamWentworth/haven/internal/model"
)

type Collector interface {
	Collect(context.Context) model.SecuritySnapshot
}

func NewForCurrentPlatform() Collector {
	if runtime.GOOS == "windows" {
		return NewWindowsCollector(NewPowerShellRunner(30 * time.Second))
	}
	if runtime.GOOS == "linux" {
		return NewLinuxCollector(NewOSCommandRunner(12 * time.Second))
	}

	return unsupportedCollector{}
}

type unsupportedCollector struct{}

func (unsupportedCollector) Collect(context.Context) model.SecuritySnapshot {
	hostName, err := os.Hostname()
	if err != nil || hostName == "" {
		hostName = "Unknown device"
	}

	return model.SecuritySnapshot{
		CollectedAt: time.Now().UTC(),
		Device: model.DeviceSummary{
			HostName:        hostName,
			OperatingSystem: runtime.GOOS,
			Architecture:    runtime.GOARCH,
		},
		FirewallProfiles: []model.FirewallProfileStatus{},
		Connections:      []model.NetworkConnection{},
		Notices: []model.CollectorNotice{{
			Source:   "Platform collector",
			Severity: "information",
			Message:  fmt.Sprintf("Native %s collection has not been enabled yet.", runtime.GOOS),
		}},
	}
}
