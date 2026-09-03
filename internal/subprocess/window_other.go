//go:build !windows

package subprocess

import "os/exec"

// HideWindow is a no-op on platforms without Windows console allocation.
func HideWindow(_ *exec.Cmd) {}
