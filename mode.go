package auth

import (
	"webtyp.com/ddl"
	"webtyp.com/model"
	"webtyp.com/orm"
	"webtyp.com/router"
	"webtyp.com/securityevent"
)

// Mode is one sign-in mode as an app chooses it: a value with the mode's settings, listed in the app's
// configuration. The composition root builds each one with the pieces it shares (Ports) and mounts the result; it
// never knows which mode it is.
//
//	SignIn: []auth.Mode{trustedip.Mode{Devices: staffmanager.Definition}, passkey.Mode{Origin: "https://app.example.com"}}
type Mode interface {
	Build(p Ports) (Authenticator, error)
}

// ModeWithTables is a Mode that keeps its own tables (passkey keeps the credentials). The app's migration calls
// Migrate for each chosen mode that has it; a mode without tables does not implement it.
type ModeWithTables interface {
	Migrate(conn ddl.Execer, c ddl.Compiler) error
}

// StepUpIssuer starts a session proven by a second factor (a passkey).
type StepUpIssuer interface {
	IssueStepUpSession(ctx router.Context, userID string) error
}

// PrincipalReader says who a request is without touching it.
type PrincipalReader interface {
	CurrentPrincipal(ctx router.Context) (Principal, error)
}

// Ports are the pieces every mode may use. authority fills the identity and session ones; the composition root adds
// what joins other libraries (MakeAdmin, HasAdmin, Built). A mode reads only what it needs.
type Ports struct {
	Identities IdentityStore          // users and their identities per provider
	Registry   ProviderRegistry       // whether a provider has any identity yet
	Sessions   SessionIssuer          // starts the main session
	StepUp     StepUpIssuer           // starts a session proven by a second factor
	Principal  PrincipalReader        // who the current request is
	Report     securityevent.Reporter // where the mode reports what is suspicious
	DB         *orm.DB                // for a mode with its own tables
	IDs        model.IDGenerator      // ids for the records a mode creates
	TrustProxy bool                   // whether X-Forwarded-For may be trusted (see ClientIP)
	Log        func(...any)           // the app's log, for what the person running the server must read
	Limiter    RateLimiter            // the app's one limit of sign-in attempts per IP, shared by every mode

	// MakeAdmin gives userID the administrator role. Used once, by the mode that creates the first administrator.
	MakeAdmin func(userID string) error
	// HasAdmin reports whether any administrator exists, whichever mode created it.
	HasAdmin func() (bool, error)
	// Built returns the module the app built for def (for example the register of trusted devices).
	Built func(def model.ModuleDefinition) (model.ModuleNaming, error)
}

// MigrateModes is the migration step of the chosen sign-in modes: it creates the tables of each one that keeps
// tables (ModeWithTables) and skips the rest (D82). The app's generated migration lists it after the users' tables.
//
//	{Name: "signin_modes", Run: auth.MigrateModes(config.App.SignIn)}
func MigrateModes(modes []Mode) func(conn ddl.Execer, c ddl.Compiler) error {
	return func(conn ddl.Execer, c ddl.Compiler) error {
		for _, m := range modes {
			if t, ok := m.(ModeWithTables); ok {
				if err := t.Migrate(conn, c); err != nil {
					return err
				}
			}
		}
		return nil
	}
}
