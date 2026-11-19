//go:build !dev || wasm

package authority

// newDevAutologin leaves every hook nil in every build without -tags dev
// (and in the browser build, which never serves a login):
// DEV_AUTOLOGIN is not even read, so setting it on a server does nothing.
func newDevAutologin(*Module) devAutologin { return devAutologin{} }
