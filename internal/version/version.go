// Package version carries the single authoritative GoLAPS version string.
// It lives in its own GOOS-neutral package so the darwin agent, the Windows
// agent and the build tooling all read (and inject into) the same constant.
package version

// Version is rewritten in place by scripts/build/build.sh during a release.
const Version = "1.2.4"
