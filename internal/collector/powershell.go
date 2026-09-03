package collector

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/AdamWentworth/haven/internal/subprocess"
)

type ScriptRunner interface {
	Run(context.Context, string) ([]byte, error)
}

type PowerShellRunner struct {
	timeout time.Duration
}

func NewPowerShellRunner(timeout time.Duration) *PowerShellRunner {
	return &PowerShellRunner{timeout: timeout}
}

func (r *PowerShellRunner) Run(ctx context.Context, script string) ([]byte, error) {
	commandContext, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	command := exec.CommandContext(
		commandContext,
		"powershell.exe",
		"-NoLogo",
		"-NoProfile",
		"-NonInteractive",
		"-Command",
		"$source = [Console]::In.ReadToEnd(); & ([ScriptBlock]::Create($source))",
	)
	subprocess.HideWindow(command)
	// The collector script is fixed at build time, but is intentionally sent
	// over stdin so it cannot exceed Windows' process command-line limit. This
	// also avoids writing a temporary script containing a posture observation.
	command.Stdin = strings.NewReader(script)

	output, err := command.Output()
	if errors.Is(commandContext.Err(), context.DeadlineExceeded) {
		return nil, fmt.Errorf("PowerShell collection exceeded the %s limit", r.timeout)
	}
	if err != nil {
		var exitError *exec.ExitError
		if errors.As(err, &exitError) {
			message := strings.TrimSpace(string(exitError.Stderr))
			if message != "" {
				return nil, fmt.Errorf("PowerShell collection failed: %s", message)
			}
		}
		return nil, fmt.Errorf("PowerShell collection failed: %w", err)
	}

	if len(strings.TrimSpace(string(output))) == 0 {
		return nil, errors.New("PowerShell collection returned no data")
	}

	return output, nil
}
