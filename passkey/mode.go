package passkey

import (
	"webtyp.com/auth"
	"webtyp.com/ddl"
	"webtyp.com/fmt"
)

// Mode is sign-in with a passkey: the key never leaves the person's device and only works on the app's domain. It is
// the recommended mode from outside a closed network.
//
//	SignIn: []auth.Mode{passkey.Mode{Origin: "https://app.example.com"}}
type Mode struct {
	Origin string // exactly what the browser shows in the address bar, port included
}

// Build makes the mode with the pieces of p. While no administrator exists it writes a one-time setup code in the log
// (D81): whoever presents it enrolls their passkey and becomes the administrator.
func (k Mode) Build(p auth.Ports) (auth.Authenticator, error) {
	sessions := struct {
		auth.PrincipalReader
		auth.StepUpIssuer
	}{p.Principal, p.StepUp}
	m, err := New(p.DB, p.IDs, sessions, p.Report, k.Origin)
	if err != nil {
		return nil, err
	}
	m.limiter = p.Limiter
	if p.HasAdmin == nil || p.MakeAdmin == nil {
		return m, nil
	}
	exists, err := p.HasAdmin()
	if err != nil {
		return nil, err
	}
	if exists {
		return m, nil
	}
	code, err := newSetupCode()
	if err != nil {
		return nil, err
	}
	m.setup = &firstAdminSetup{code: code, users: p.Identities, hasAdmin: p.HasAdmin, makeAdmin: p.MakeAdmin}
	if p.Log != nil {
		p.Log(fmt.Err(msgSetupCode).Error(), code)
	}
	return m, nil
}

// Migrate creates the passkey tables; the app's migration calls it because this mode keeps tables (D82).
func (Mode) Migrate(conn ddl.Execer, c ddl.Compiler) error { return Migrate(conn, c) }

var (
	_ auth.Mode           = Mode{}
	_ auth.ModeWithTables = Mode{}
)
