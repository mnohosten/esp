package version

import (
	"fmt"
	"runtime"
)

// These variables are set at build time via ldflags
var (
	// Version is the semantic version of the build
	Version = "dev"

	// Commit is the git commit SHA
	Commit = "unknown"

	// BuildTime is the time the binary was built
	BuildTime = "unknown"
)

// Info returns version information as a formatted string
func Info() string {
	return fmt.Sprintf("ESP Server %s (commit: %s, built: %s, go: %s)",
		Version, Commit, BuildTime, runtime.Version())
}

// Short returns just the version string
func Short() string {
	return Version
}

// Full returns detailed version information
func Full() map[string]string {
	return map[string]string{
		"version":    Version,
		"commit":     Commit,
		"build_time": BuildTime,
		"go_version": runtime.Version(),
		"os":         runtime.GOOS,
		"arch":       runtime.GOARCH,
	}
}
