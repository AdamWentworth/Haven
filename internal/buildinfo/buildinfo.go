// Package buildinfo exposes the public HAVEN release identity to the API and
// command binaries. Revision is replaced by release builds with -ldflags.
package buildinfo

const Version = "0.14.0"

var Revision = "development"
