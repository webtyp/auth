package auth

import (
	"webtyp.com/events"
	"webtyp.com/fmt"
	"webtyp.com/input"
	"webtyp.com/model"
	"webtyp.com/router"
	"webtyp.com/time"
	"webtyp.com/user"
)

// domainError is the concrete type of this package's sentinel errors. IsX
// recognises them with a type assertion: TinyGo compiles that to a type-code
// comparison, while == between two error values goes through
// runtime.interfaceEqual and pulls internal/reflectlite into the wasm binary.
type domainError string

func (e domainError) Error() string { return string(e) }

const (
	ErrInvalidCredentials domainError = "access denied"    // EN: Access Denied                    / ES: Acceso Denegado
	ErrSuspended          domainError = "user suspended"   // EN: User Suspended                   / ES: Usuario Suspendido
	ErrEmailTaken         domainError = "email registered" // EN: Email Registered                 / ES: Correo electrónico Registrado
	ErrWeakPassword       domainError = "password weak"    // EN: Password Weak                    / ES: Contraseña Débil
	ErrSessionExpired     domainError = "token expired"    // EN: Token Expired                    / ES: Token Expirado
	ErrNotEditable        domainError = "field not editable"
	ErrNotFound           domainError = "user not found"         // EN: User Not Found                   / ES: Usuario No Encontrado
	ErrProviderNotFound   domainError = "provider not found"     // EN: Provider Not Found               / ES: Proveedor No Encontrado
	ErrInvalidOAuthState  domainError = "state invalid"          // EN: State Invalid                    / ES: Estado Inválido
	ErrCannotUnlink       domainError = "identity cannot unlink" // EN: Identity Cannot Unlink           / ES: Identidad No puede Desvincular
	ErrInvalidRUT         domainError = "rut invalid"            // EN: Rut Invalid                      / ES: Rut Inválido
	ErrRUTTaken           domainError = "rut registered"         // EN: Rut Registered                   / ES: Rut Registrado
	ErrIPTaken            domainError = "ip registered"          // EN: Ip Registered                    / ES: Ip Registrado
)

// IsNotFound reports whether err is ErrNotFound.
func IsNotFound(err error) bool {
	e, ok := err.(domainError)
	return ok && e == ErrNotFound
}

// IsInvalidRUT reports whether err is ErrInvalidRUT.
func IsInvalidRUT(err error) bool {
	e, ok := err.(domainError)
	return ok && e == ErrInvalidRUT
}

// IsRUTTaken reports whether err is ErrRUTTaken.
func IsRUTTaken(err error) bool {
	e, ok := err.(domainError)
	return ok && e == ErrRUTTaken
}

// EnvDevAutologin names the development auto-login variable. Its value is the
// exact JSON body the login form POSTs (e.g. {"code":"12345678-9"}), or a JSON
// list of them, one per user to test: [{"code":"12345678-9"},{"code":"9876543-2"}].
// Credential 1 signs in on localhost, credential N on userN.localhost. When it
// is set, authority replays it through the enabled authenticators' Login and
// issues a real session. Absent or empty = production behaviour. Honored only
// in builds with -tags dev; every other build ignores it entirely.
const EnvDevAutologin = "DEV_AUTOLOGIN"

// FormLogin is implemented by an Authenticator whose login is a form POST.
// Login runs EVERY check the POST route runs (rate limit, credential, account
// status, trusted IP) against body — the same bytes the form sends — and
// returns the user id. It never writes a response and never issues a session:
// the caller does.
type FormLogin interface {
	Login(ctx router.Context, body []byte) (userID string, err error)
}

type OAuthUserInfo struct {
	ID            string
	Email         string
	Name          string
	Avatar        string
	EmailVerified bool
}

// OAuthToken is what a provider returns when it exchanges the code. It replaces
// oauth2.Token: that type dragged net/http in, and net/http does not exist under TinyGo —
// which put this whole module out of the edge for one function call.
type OAuthToken struct {
	AccessToken string
	TokenType   string
	ExpiresIn   int
}

func (t *OAuthToken) DecodeFields(r model.FieldReader) {
	t.AccessToken, _ = r.String("access_token")
	t.TokenType, _ = r.String("token_type")
	exp, _ := r.Int("expires_in")
	t.ExpiresIn = int(exp)
}

func (t OAuthToken) IsNil() bool { return false }

// OAuthConfig is the provider's registration: what the app declares in the provider console.
type OAuthConfig struct {
	ClientID     string
	ClientSecret string
	RedirectURL  string
	Scopes       []string
	AuthURL      string // provider's authorization endpoint
	TokenURL     string // provider's token endpoint
}

type OAuthProvider interface {
	Name() string
	AuthCodeURL(state string) string
	ExchangeCode(code string) (OAuthToken, error)
	GetUserInfo(token OAuthToken) (OAuthUserInfo, error)
}

// Authenticator is one login mode. It owns its HTTP routes completely — authority
// never inspects, duplicates, or knows the shape of what it mounts.
type Authenticator interface {
	Name() string
	Mount(r router.Router)
}

// SessionPolicy is how long a session lives and how strongly it was proven.
// Each session row stores its own policy, so different strategies can share
// one session table.
type SessionPolicy struct {
	Absolute  time.Unix       // duration from creation (e.g. 8*time.Hour); the hard cap. Required (> 0).
	Idle      time.Unix       // duration without activity; 0 = no idle limit
	Assurance model.Assurance // what a session issued under this policy proves
}

// Principal is who a request is, and how strongly that was proven. (The name
// Identity is taken: it is the provider-link model of the "identity" table,
// which must NOT be renamed — its ModelName is a table name.)
type Principal struct {
	UserID    string
	Assurance model.Assurance
	IssuedAt  time.Unix // when the session was created; 0 for request credentials
}

// ErrMsgPolicyAbsolute is what a SessionPolicy without a hard cap is refused with.
const ErrMsgPolicyAbsolute = "auth: SessionPolicy.Absolute must be > 0"

// SessionStrategy is how identity survives across requests after a successful
// login. authority holds one main strategy (default: session/cookie) and
// one step-up strategy, both built by default; the consumer may swap them via
// Module.SetStrategy and Module.SetStepUpStrategy before mounting. Implementation: session/cookie.
type SessionStrategy interface {
	Issue(ctx router.Context, userID string) error  // starts a session, writes the credential onto ctx's response
	Identify(ctx router.Context) (Principal, error) // reads the incoming credential; zero Principal only alongside a non-nil err
	Revoke(ctx router.Context) error                // ends the session named by ctx's incoming credential
}

// RequestIdentifier is an Authenticator that identifies a request from a
// credential it carries (a header), not from a session. handled == true
// means the request presented this kind of credential: the result (which may
// be the zero Principal, if the credential was invalid) is final and no
// session cookie is consulted.
type RequestIdentifier interface {
	IdentifyRequest(ctx router.Context) (p Principal, handled bool)
}

// --- Ports a mode receives at construction. It asks for ONLY the ones it needs —
// none of these is a "god interface"; authority implements all of them, a mode
// never sees *authority.Module itself. ---

// SessionIssuer lets a mode start a session after verifying credentials, without
// knowing whether the app carries it in a cookie or a signed JWT.
type SessionIssuer interface {
	IssueSession(ctx router.Context, userID string) error
}

// SubjectStore resolves or creates a stable identity for a local development
// scenario. The local authenticator uses it to materialize the selected
// Scenario without ever contacting an external provider.
type SubjectStore interface {
	GetOrCreateSubject(id user.SubjectID, email, name, avatar string) (user.Subject, error)
}

// IdentityStore is the persistence port a mode uses to resolve or register the
// domain User/Identity behind a credential. A mode never queries *orm.DB itself.
// GivesSignIn is an optional capability of an Authenticator: it creates the account a person signs in with from the
// credential that mode uses (a RUT for trusted_ip), or returns the one that already has it. The app's staff module
// calls it when a professional is saved, so the person can sign in without a second form.
//
//	userID, err := giver.GiveSignIn("8.123.456-6", "Dra. Ana Rojas")
type GivesSignIn interface {
	GiveSignIn(credential, name string) (userID string, err error)
}

type IdentityStore interface {
	UserByID(id string) (User, error)
	UserByEmail(email string) (User, error)
	CreateUser(email, name, phone string) (User, error)
	// IdentityByProvider finds who owns a (provider, providerID) pair — an OAuth
	// (provider name, external subject) or a trusted_ip (provider="trusted_ip",
	// the normalized RUT).
	IdentityByProvider(provider, providerID string) (Identity, error)
	// IdentityFor returns userID's identity row for provider — e.g. email_password
	// reads its bcrypt hash from Identity.ProviderId here.
	IdentityFor(userID, provider string) (Identity, error)
	UpsertIdentity(userID, provider, providerID, email string) error
	// DeleteIdentity removes userID's identity of provider (the mode that owns the credential removes it).
	DeleteIdentity(userID, provider string) error
	UpdateUserAvatar(userID, avatar string) error
}

// StateStore is the anti-CSRF port the oauth2 mode uses for its one-time state
// token. authority owns the oauth_state table; a mode never touches it directly.
type StateStore interface {
	// CreateState devuelve el state (viaja en la URL del proveedor) y el nonce
	// (viaja en una cookie del navegador). Los dos hacen falta para consumirlo:
	// el state solo prueba que ALGUIEN inició un login, el nonce prueba que fue
	// ESTE navegador. Sin el segundo, un atacante inicia el login, se queda con
	// su propio code y empuja a la víctima al callback — la víctima termina con
	// la sesión del atacante.
	CreateState(provider string) (state, nonce string, err error)

	// ConsumeState valida state+nonce y borra la fila. Single-use.
	ConsumeState(state, nonce, provider string) error
}

// TrustedIPStore is the read-only port the trusted_ip mode uses to check whether
// a request's IP is on userID's allowlist. Kept separate from IdentityStore
// because an allowed IP is not a login credential — it's an authorization check
// applied AFTER the RUT already identified the auth.
type TrustedIPStore interface {
	IsTrustedIP(userID, ip string) bool
}

// ProviderRegistry answers whether a provider has ANY identity registered yet
// — the "is this a fresh install?" question a first-run setup asks. Separate
// from IdentityStore, which only ever resolves ONE known identity: this asks
// about the emptiness of the whole provider, which is a different question and
// the only one PathSetup needs.
type ProviderRegistry interface {
	HasIdentity(provider string) (bool, error)
}

// SessionRepo is the storage port a SessionStrategy uses to persist stateful
// sessions. authority.Module implements it with its own table + cache.
type SessionRepo interface {
	CreateSession(userID, ip, userAgent string, p SessionPolicy) (Session, error)
	GetSession(id string) (Session, error) // applies the row's own policy; slides idle
	DeleteSession(id string) error
}

// ClientIP extracts the caller's IP from ctx. When trustProxy is true it reads
// X-Forwarded-For / X-Real-IP first (only safe behind a reverse proxy you control —
// otherwise a client can spoof its own IP). Shared by every mode/strategy that
// needs an IP for a SecurityEvent or an audit column: it is mechanism-agnostic,
// so it lives at the root, not inside any one mode. The result is canonical
// (input.CanonicalIP): compare it only against IPs stored in that same form.
func ClientIP(ctx router.Context, trustProxy bool) string {
	return input.CanonicalIP(rawClientIP(ctx, trustProxy))
}

// rawClientIP is ClientIP before canonicalisation. Every trusted-IP comparison
// needs the IP stored and the IP observed in one spelling (one "localhost" is
// ::1 from one client and 127.0.0.1 from another), so no path out of ClientIP
// may skip input.CanonicalIP — hence one wrapper, not a call per return.
func rawClientIP(ctx router.Context, trustProxy bool) string {
	if trustProxy {
		xff := ctx.GetHeader("X-Forwarded-For")
		if xff != "" {
			parts := fmt.Split(xff, ",")
			return fmt.Convert(parts[0]).TrimSpace().String()
		}
		xri := ctx.GetHeader("X-Real-IP")
		if xri != "" {
			return fmt.Convert(xri).TrimSpace().String()
		}
	}
	if addr := ctx.Value(router.ContextKeyRemoteAddr); addr != "" {
		return HostFromAddr(addr)
	}
	return ""
}

// HostFromAddr splits the host out of a net/http-style "host:port" address,
// respecting the brackets net.JoinHostPort puts around an IPv6 literal
// ("[::1]:54321" → "::1"). Splitting naively on ":" (this function's
// predecessor) returns "[" for any IPv6 address — a real bug, previously
// leaf-patched in veltylabs/staff_manager (normalizeIP/ipsEqual) instead of
// fixed here; that patch is retired once this ships.
func HostFromAddr(addr string) string {
	if len(addr) > 0 && addr[0] == '[' {
		if end := fmt.Index(addr, "]"); end != -1 {
			return addr[1:end]
		}
		return addr
	}
	if idx := fmt.LastIndex(addr, ":"); idx != -1 {
		return addr[:idx]
	}
	return addr
}

// GrantLister lists the grants a subject holds within a project, as stored: a
// wildcard grant stays {Resource: model.Wildcard}. rbac.Service satisfies it
// structurally (SubjectGrants); auth never imports rbac — the composition root
// injects it.
type GrantLister interface {
	SubjectGrants(projectID, subjectID string) ([]model.Grant, error)
}

// Permissions configures the crud read me to send the caller's grants.
// nil (the default) ⇒ me sends no grants — closed by default.
type Permissions struct {
	Grants    GrantLister
	ProjectID string
}

type Config struct {
	// CookieName/TokenTTL configure authority's OWN default session strategy
	// (session/cookie). TokenTTL is the ABSOLUTE lifetime of its sessions: an
	// active session still ends after it. The default cookie is host-only and
	// named "__Host-"+CookieName.
	CookieName string    // default: "session"
	TokenTTL   time.Unix // duration; default: time.Day

	// TrustProxy tells every IP-extracting collaborator (the default cookie
	// strategy, Module.LoginLAN) whether to trust X-Forwarded-For/X-Real-IP.
	// The composition root passes this SAME value to any mode it constructs
	// that also needs it (trusted_ip.New's trustProxy param, WithTrustProxy on
	// the others) — one environmental fact, told explicitly to every consumer,
	// same idiom as IDs/Events.
	TrustProxy bool

	// IDs mints primary keys for every record this module creates. REQUIRED:
	// New fails if nil — an auth module must never silently pick its own
	// generator.
	IDs model.IDGenerator

	// Events is the app's broker. REQUIRED: New fails if nil. Every security
	// event of this module and of its modes is reported on it through
	// webtyp.com/securityevent, so an attack is never dropped silently.
	Events events.Publisher

	// Permissions, when set, makes the crud read me compose identity (this module) with
	// authorization (the injected GrantLister) into me.grants.
	Permissions *Permissions

	// IdleTTL, when > 0, ends a session of the default strategy after IdleTTL
	// WITHOUT activity, sliding, but never beyond TokenTTL. 0 (default)
	// = no idle limit. Together with TokenTTL they build the default policy
	// SessionPolicy{Absolute: TokenTTL, Idle: IdleTTL, Assurance: SingleFactor}.
	IdleTTL time.Unix // duration
}

const (
	PathLogin  = "/login"
	PathLogout = "/logout"

	// PathDevAutologinTabs answers, only in builds with -tags dev and only to a
	// loopback caller, the hosts of the tabs DEV_AUTOLOGIN signs in, one per
	// credential in its order: ["localhost","user2.localhost",…]. The webtyp
	// dev environment opens one browser tab per host. Absent in every other build.
	PathDevAutologinTabs = "/_dev/autologin/tabs"

	// PathAfterLogin is where every authenticator redirects once a session
	// exists. It is the WASM application shell, not the site root: "/" is
	// where the pre-login screen lives, so redirecting there would bounce a
	// user who just authenticated straight back to the login form.
	//
	// The value MUST stay equal to sitec.ShellPath, which is the constant the
	// site compiler uses to emit that document. This package cannot import
	// sitec to say so — sitec is a build-time compiler over os/path/filepath
	// and auth compiles to WASM — so the test that pins the two together
	// lives in sitec, which imports auth freely. Changing one without the
	// other fails that test.
	PathAfterLogin = "/app/"

	// PathLoginRUT is where trusted_ip.Authenticator mounts the LAN
	// device-trust login route. A client builds its login form from
	// RUTLoginDataModel and posts here — no hardcoded literal anywhere else
	// in the repo. The value is deliberately generic ("/session", not
	// "/login/rut"): this mode's whole point is that an outsider watching
	// network traffic must not learn what kind of credential the single
	// field asks for. The Go symbol keeps naming the mode it belongs to;
	// only the wire value is neutral. Do not "fix" it back — see
	// docs/PLAN.md in veltylabs/mjosefa-cms for the leak this closed.
	PathLoginRUT = "/session"

	// PathSetup is the first-run route trusted_ip.Authenticator mounts when
	// the consumer enables WithFirstAdminSetup: it answers "is this a fresh
	// install?" (GET) and creates the very first administrator (POST), and
	// both close permanently the moment one identity exists for the provider.
	// It solves the chicken-and-egg of a device-trust system — only an admin
	// can assign devices, but nobody can log in until an admin exists —
	// without the consumer having to carry bootstrap credentials in its
	// environment.
	PathSetup = "/setup"

	// PathOAuthPrefix es la raiz bajo la que oauth2.Authenticator monta sus
	// rutas. Es la unica definicion de esa cadena en el repositorio.
	PathOAuthPrefix = "/oauth/"
)

// ProviderTrustedIP is the auth.Identity provider name under which the
// normalized RUT of a LAN user is stored.
const ProviderTrustedIP = "trusted_ip"

// ProviderCloudflareAccess is the Identity.Provider of an e-mail that
// Cloudflare Access verified (package cfaccess); ProviderId is that e-mail.
const ProviderCloudflareAccess = "cloudflare_access"

// PathOAuthStart devuelve la ruta que inicia el intercambio OAuth2 con el
// proveedor indicado. Un consumidor enlaza aqui su boton de "iniciar sesion".
func PathOAuthStart(provider string) string {
	return PathOAuthPrefix + provider
}

// PathOAuthCallback devuelve la ruta a la que el proveedor redirige de vuelta.
// Es el valor que se registra como URI de redireccion en la consola del
// proveedor, precedido del dominio publico de la aplicacion.
func PathOAuthCallback(provider string) string {
	return PathOAuthPrefix + "callback/" + provider
}

// User is the contract's view of a user: what the identity ports hand to callers. The module stores it as
// authority.User (a model it mounts through crud) and converts at the port.
type User struct {
	Id        string
	Email     string
	Name      string
	Phone     string
	Status    string
	Avatar    string
	CreatedAt time.Unix
}

// Identity is the contract's view of a provider identity of a user (password, oauth, trusted_ip…).
type Identity struct {
	Id         string
	UserId     string
	Provider   string
	ProviderId string
	Email      string
	CreatedAt  time.Unix
}

// Session is the contract's view of a session.
type Session struct {
	Id          string
	UserId      string
	ExpiresAt   time.Unix
	Ip          string
	UserAgent   string
	CreatedAt   time.Unix
	AbsoluteAt  time.Unix
	IdleSeconds time.Unix
	Assurance   int64
}
