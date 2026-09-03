//go:build windows

package subprocess

import (
	"os/exec"
	"syscall"
)

const createNoWindow = 0x08000000

// HideWindow prevents fixed background collectors and actions from allocating
// or showing a Windows console. Pipes for stdin, stdout, and stderr continue to
// work, so callers retain structured output and exit-code handling.
func HideWindow(command *exec.Cmd) {
	if command.SysProcAttr == nil {
		command.SysProcAttr = &syscall.SysProcAttr{}
	}
	command.SysProcAttr.HideWindow = true
	command.SysProcAttr.CreationFlags |= createNoWindow
}
