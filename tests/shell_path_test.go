package tests

import (
	"testing"

	"webtyp.com/auth"
	"webtyp.com/sitec"
)

// TestPathAfterLoginIsTheShell pins auth.PathAfterLogin to sitec.ShellPath.
//
// The two constants describe the same document from opposite ends: sitec emits
// the WASM application shell at ShellPath, and every authenticator redirects
// there once a session exists. They cannot be a single constant — the root
// webtyp.com/auth module compiles to WASM and sitec is a build-time compiler
// over os/path/filepath, so auth importing sitec would drag a toolchain into
// the browser binary.
//
// This test module is where the two CAN meet: it exists precisely to hold test
// dependencies the root module must not carry (see the note atop go.mod). If
// one constant moves without the other, the app-shell redirect silently points
// at a document nobody emits — a 404 right after a successful login, with no
// compile error anywhere to catch it.
func TestPathAfterLoginIsTheShell(t *testing.T) {
	if auth.PathAfterLogin != sitec.ShellPath {
		t.Fatalf("auth.PathAfterLogin = %q, sitec.ShellPath = %q — they must name the same document; change both or neither",
			auth.PathAfterLogin, sitec.ShellPath)
	}
}
