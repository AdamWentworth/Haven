package webui

import (
	"embed"
	"io/fs"
)

// The Vite build writes into dist before the Go executable is compiled.
// The placeholder keeps ordinary Go tooling functional in a fresh checkout.
//
//go:embed all:dist
var assets embed.FS

func Files() (fs.FS, error) {
	return fs.Sub(assets, "dist")
}
