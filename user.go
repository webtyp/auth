package auth

import (
	"webtyp.com/events"
	"webtyp.com/fmt"
	"webtyp.com/model"
	"webtyp.com/router"
	"webtyp.com/user"
)

var (
	ErrInvalidCredentials = fmt.Err("access", "denied")             // EN: Access Denied                    / ES: Acceso Denegado
	ErrSuspended          = fmt.Err("user", "suspended")            // EN: User Suspended                   / ES: Usuario Suspendido
	ErrEmailTaken         = fmt.Err("email", "registered")          // EN: Email Registered                 / ES: Correo electrónico Registrado
	ErrWeakPassword       = fmt.Err("password", "weak")             // EN: Password Weak                    / ES: Contraseña Débil
	ErrSessionExpired     = fmt.Err("token", "expired")             // EN: Token Expired                    / ES: Token Expirado
	ErrNotFound           = fmt.Err("user", "not", "found")         // EN: User Not Found                   / ES: Usuario No Encontrado
	ErrProviderNotFound   = fmt.Err("provider", "not", "found")     // EN: Provider Not Found               / ES: Proveedor No Encontrado
	ErrInvalidOAuthState  = fmt.Err("state", "invalid")             // EN: State Invalid                    / ES: Estado Inválido
	ErrCannotUnlink       = fmt.Err("identity", "cannot", "unlink") // EN: Identity Cannot Unlink           / ES: Identidad No puede Desvincular
	ErrInvalidRUT         = fmt.Err("rut", "invalid")               // EN: Rut Invalid                      / ES: Rut Inválido
	ErrRUTTaken           = fmt.Err("rut", "registered")            // EN: Rut Registered                   / ES: Rut Registrado
	ErrIPTaken            = fmt.Err("ip", "registered")             // EN: Ip Registered                    / ES: Ip Registrado
)

type SecurityEventType uint8

const (
	EventJWTTampered        SecurityEventType = iota // validateJWT: jwt.Forged (never jwt.Expired)
	EventOAuthReplay                                 // consumeState: state already consumed (2nd use)
	EventOAuthExpiredState                           // consumeState: state found but past ExpiresAt
	EventOAuthCrossProvider                          // consumeState: provider mismatch (state preserved)
	EventIPMismatch                                  // LoginLAN: IP not registered
	EventNonActiveAccess                             // Login/LoginLAN: status != "active"
	EventUnauthorizedAccess                          // validateSession: cookie present but session invalid
	EventAccessDenied                                // AccessCheck: RBAC denied with valid session
	EventPermissionCorrupt                           // HasPermission: permissions.action is not a CRUD string
	EventRateLimited                                 // POST /login: Config.RateLimit rejected the attempt before bcrypt
	EventInvalidRUT                                  // trusted_ip: the typed value is not a checksum-valid RUT (probe or typo)
	EventUnknownRUT                                  // trusted_ip: valid RUT, no identity registered for it
)

type SecurityEvent struct {
	Type      SecurityEventType
	IP        string // client IP, empty if not available
	UserID    string // empty if user not yet identified
	Provider  string // OAuth provider name, for OAuth events
	Resource  string // RBAC resource, for EventAccessDenied
	Timestamp int64  // time.Now().Unix()
}

func (e *SecurityEvent) EncodeFields(w model.FieldWriter) {
	w.Int("type", int64(e.Type))
	w.String("ip", e.IP)
	w.String("user_id", e.UserID)
	w.String("provider", e.Provider)
	w.String("resource", e.Resource)
	w.Int("timestamp", e.Timestamp)
}

func (e *SecurityEvent) IsNil() bool { return e == nil }

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

// SessionStrategy is how identity survives across requests after a successful
// login. authority holds exactly one (default: session/cookie); the consumer may
// swap it via Module.SetStrategy before mounting. Implementations: session/cookie,
// session/jwt.
type SessionStrategy interface {
	Issue(ctx router.Context, userID string) error          // starts a session, writes the credential onto ctx's response
	Identify(ctx router.Context) (userID string, err error) // reads the incoming credential; "" only alongside a non-nil err
	Revoke(ctx router.Context) error                        // ends the session named by ctx's incoming credential
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

// SecurityNotifier lets a mode report a SecurityEvent without knowing whether
// anything is subscribed.
type SecurityNotifier interface {
	Notify(e SecurityEvent)
}

// SessionRepo is the storage port a SessionStrategy uses to persist stateful
// sessions. authority.Module implements it with its own table + cache.
type SessionRepo interface {
	CreateSession(userID, ip, userAgent string) (Session, error)
	GetSession(id string) (Session, error)
	DeleteSession(id string) error
}

// ClientIP extracts the caller's IP from ctx. When trustProxy is true it reads
// X-Forwarded-For / X-Real-IP first (only safe behind a reverse proxy you control —
// otherwise a client can spoof its own IP). Shared by every mode/strategy that
// needs an IP for a SecurityEvent or an audit column: it is mechanism-agnostic,
// so it lives at the root, not inside any one mode.
func ClientIP(ctx router.Context, trustProxy bool) string {
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
		parts := fmt.Split(addr, ":")
		if len(parts) > 0 {
			return parts[0]
		}
		return addr
	}
	return ""
}

// ActionResolver resolves which actions a subject holds on one resource.
// rbac.Service satisfies it structurally (AllowedActions); auth never
// imports rbac — the composition root injects it.
type ActionResolver interface {
	AllowedActions(projectID, subjectID string, resource model.Resource) model.Action
}

// Permissions configures opMe to populate ProfileDTO.Permissions.
// nil (the default) ⇒ opMe returns no permissions — closed by default.
type Permissions struct {
	Resolver  ActionResolver
	ProjectID string
	Resources []model.Resource
}

type Config struct {
	// CookieName/TokenTTL configure authority's OWN default session strategy
	// (session/cookie) and the lifetime of every session row it creates,
	// regardless of which strategy ends up carrying the credential.
	CookieName string // default: "session"
	TokenTTL   int    // default: 86400 (seconds)

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

	// Events receives security events (TopicSecurity). Optional: nil = events
	// are dropped (fire-and-forget contract), never an error.
	Events events.Publisher

	// OnPasswordValidate is consulted by Module.SetPassword before hashing.
	// Return a non-nil error to reject the password. nil = only the built-in
	// len>=8 check applies.
	OnPasswordValidate func(password string) error

	// Permissions, when set, makes opMe compose identity (this module) with
	// authorization (the injected resolver) into ProfileDTO.Permissions.
	Permissions *Permissions

	// IdleTTL, when > 0, makes sessions expire after IdleTTL seconds WITHOUT
	// activity, sliding: every authenticated GetSession pushes ExpiresAt to
	// now+IdleTTL. It supersedes TokenTTL for both initial and renewed
	// lifetime. 0 (default) ⇒ today's fixed-TokenTTL behavior, unchanged.
	IdleTTL int
}

const (
	PathLogin      = "/login"
	PathLogout     = "/logout"
	PathAfterLogin = "/"

	// PathLoginRUT is where trusted_ip.Authenticator mounts the LAN RUT
	// login route. A client builds its login form from RUTLoginDataModel
	// and posts here — no hardcoded literal anywhere else in the repo.
	PathLoginRUT = "/login/rut"

	// PathOAuthPrefix es la raiz bajo la que oauth2.Authenticator monta sus
	// rutas. Es la unica definicion de esa cadena en el repositorio.
	PathOAuthPrefix = "/oauth/"
)

// ProviderTrustedIP is the auth.Identity provider name under which the
// normalized RUT of a LAN user is stored.
const ProviderTrustedIP = "trusted_ip"

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

// TopicSecurity is the events topic every SecurityEvent is published on.
const TopicSecurity = "auth.security"

// Op names — shared vocabulary between the wasm view and the server module.
const (
	OpMe         = "me"          // authenticated caller's profile
	OpListUsers  = "list_users"  // admin: list users
	OpUpsertUser = "upsert_user" // admin: create (Id=="") or update
	OpDeleteUser = "delete_user" // admin: delete by record

	OpRegisterLAN   = "register_lan"   // admin: link a RUT to a user (trusted_ip identity)
	OpUnregisterLAN = "unregister_lan" // admin: remove the user's trusted_ip identity
	OpGetLAN        = "get_lan"        // admin: read the user's normalized RUT
)

// ResourceLANIdentity gates the LAN identity ops. It is deliberately NOT the
// "users" resource those ops sit next to: registering a RUT MINTS A LOGIN
// CREDENTIAL, while user administration only edits records. Bundling them
// would make "may create/update users" imply "may log in as anyone" wherever
// TrustedIPStore answers per-network rather than per-user.
//
// An app that never administers LAN identities simply never grants it —
// closed by default.
const ResourceLANIdentity model.Resource = "lan_identity"

// ProfileDTO is a safe subset of User data for public/API consumption.
type ProfileDTO struct {
	Id          string
	Name        string
	Email       string
	Avatar      string
	Roles       []string
	RoleNames   []string
	Permissions []string // "resource:actions" pairs, e.g. "service_catalog:rc"
	Locale      string
}

func (p ProfileDTO) EncodeFields(w model.FieldWriter) {
	w.String("id", p.Id)
	w.String("name", p.Name)
	w.String("email", p.Email)
	w.String("avatar", p.Avatar)
	w.String("locale", p.Locale)
	aw := w.Array("roles", len(p.Roles))
	for _, r := range p.Roles {
		aw.String(r)
	}
	aw.Close()
	awn := w.Array("role_names", len(p.RoleNames))
	for _, rn := range p.RoleNames {
		awn.String(rn)
	}
	awn.Close()
	pw := w.Array("permissions", len(p.Permissions))
	for _, perm := range p.Permissions {
		pw.String(perm)
	}
	pw.Close()
}

func (p ProfileDTO) IsNil() bool { return false }

// Grant appends one "resource:actions" entry — the ONLY producer of the
// wire format documented on Permissions.
func (p *ProfileDTO) Grant(resource model.Resource, actions model.Action) {
	if actions == 0 {
		return
	}
	p.Permissions = append(p.Permissions, string(resource)+":"+actions.String())
}

// Allows reports whether the profile carries any action on resource — the
// ONLY consumer of the format. Clients call this instead of parsing
// Permissions themselves.
func (p ProfileDTO) Allows(resource string) bool {
	prefix := resource + ":"
	for _, perm := range p.Permissions {
		if fmt.HasPrefix(perm, prefix) {
			parts := fmt.Split(perm, ":")
			return len(parts) == 2 && parts[1] != ""
		}
	}
	return false
}

func (p *ProfileDTO) DecodeFields(r model.FieldReader) {
	p.Id, _ = r.String("id")
	p.Name, _ = r.String("name")
	p.Email, _ = r.String("email")
	p.Avatar, _ = r.String("avatar")
	p.Locale, _ = r.String("locale")
	if ar, ok := r.Array("roles"); ok {
		p.Roles = make([]string, ar.Len())
		for i := 0; i < ar.Len(); i++ {
			p.Roles[i] = ar.String(i)
		}
	}
	if arn, ok := r.Array("role_names"); ok {
		p.RoleNames = make([]string, arn.Len())
		for i := 0; i < arn.Len(); i++ {
			p.RoleNames[i] = arn.String(i)
		}
	}
	if ap, ok := r.Array("permissions"); ok {
		p.Permissions = make([]string, ap.Len())
		for i := 0; i < ap.Len(); i++ {
			p.Permissions[i] = ap.String(i)
		}
	}
}

// ShellProfile is the read-only view of a session that an application shell
// renders.
//
// NOT to be confused with Identity in this package, which is the ORM row tying
// a user to an auth provider.
type ShellProfile struct {
	Name   string
	Avatar string
	Roles  []string // display names, never codes
}

func (p ShellProfile) UserName() string    { return p.Name }
func (p ShellProfile) UserAvatar() string  { return p.Avatar }
func (p ShellProfile) UserRoles() []string { return p.Roles }

// Shell converts a profile into the shape an application shell renders.
func (p ProfileDTO) Shell() ShellProfile {
	return ShellProfile{
		Name:   p.Name,
		Avatar: p.Avatar,
		Roles:  p.RoleNames,
	}
}
