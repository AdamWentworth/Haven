//go:build windows

package subprocess

import (
	"os/exec"
	"testing"
)

func TestHideWindowSuppressesConsoleAllocation(t *testing.T) {
	command := exec.Command("cmd.exe", "/c", "exit", "0")
	HideWindow(command)
	if command.SysProcAttr == nil || !command.SysProcAttr.HideWindow || command.SysProcAttr.CreationFlags&createNoWindow == 0 {
		t.Fatalf("background command is not configured for hidden, console-free execution: %#v", command.SysProcAttr)
	}
}
