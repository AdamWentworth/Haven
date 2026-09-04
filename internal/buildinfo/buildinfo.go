// Package buildinfo exposes the public HAVEN release identity to the API and
// command binaries. Revision is replaced by release builds with -ldflags.
package buildinfo

const Version = "0.15.3"

var Revision = "development"

// AgentInstallation is stamped only into packaging-specific reporter builds.
// Interactive binaries retain the safe default.
var AgentInstallation = "interactive"
