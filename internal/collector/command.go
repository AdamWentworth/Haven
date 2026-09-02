package collector

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// CommandRunner executes fixed collector commands. Callers never pass browser,
// API, or other user-controlled values into it.
type CommandRunner interface {
	Run(context.Context, string, ...string) ([]byte, error)
}

type OSCommandRunner struct {
	timeout time.Duration
}

func NewOSCommandRunner(timeout time.Duration) *OSCommandRunner {
	return &OSCommandRunner{timeout: timeout}
}

func (runner *OSCommandRunner) Run(ctx context.Context, name string, arguments ...string) ([]byte, error) {
	commandContext, cancel := context.WithTimeout(ctx, runner.timeout)
	defer cancel()

	command := exec.CommandContext(commandContext, name, arguments...)
	output, err := command.CombinedOutput()
	if errors.Is(commandContext.Err(), context.DeadlineExceeded) {
		return output, fmt.Errorf("%s collection exceeded the %s limit", name, runner.timeout)
	}
	if err != nil {
		message := strings.TrimSpace(string(output))
		if message != "" {
			return output, fmt.Errorf("%s failed: %s", name, message)
		}
		return output, fmt.Errorf("%s failed: %w", name, err)
	}
	return output, nil
}
