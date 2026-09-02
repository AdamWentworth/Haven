package collector

import (
	"context"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestPowerShellRunnerAcceptsScriptLongerThanCommandLineLimit(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("PowerShell runner is Windows-specific")
	}
	runner := NewPowerShellRunner(10 * time.Second)
	script := "$value='" + strings.Repeat("x", 40_000) + "'\n$value.Length"
	output, err := runner.Run(context.Background(), script)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(output)) != "40000" {
		t.Fatalf("unexpected PowerShell output: %q", output)
	}
}
