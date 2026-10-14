// Package clientassertion authenticates machine clients with private_key_jwt
// (RFC 7523): the client signs a short-lived JWT bound to one HTTP request
// (htm/htu) with its private key, and the server verifies it with the
// client's registered public key. The client becomes a principal that
// router's .Requires authorizes like any user.
//
// There is deliberately NO per-client lockout: there is no guessable secret
// to brute-force, and a lockout keyed on client_id would let anyone deny
// service to a legitimate client by sending bad assertions with its id.
package clientassertion

import (
	"webtyp.com/auth"
	"webtyp.com/ddl"
	"webtyp.com/fmt"
	"webtyp.com/jwt"
	"webtyp.com/model"
	"webtyp.com/orm"
	"webtyp.com/router"
	"webtyp.com/time"
)

const (
	name = "client_assertion"

	ErrMsgEmptyAudience = "clientassertion: audience is required"

	jtiSeparator = ":"
)

// Reasons recorded in EventClientAssertionRejected.
const (
	reasonMalformed     = "malformed"
	reasonUnknownClient = "unknown_client"
	reasonSignature     = "signature"
	reasonExpired       = "expired"
	reasonAudience      = "audience"
	reasonBinding       = "binding"
	reasonReplay        = "replay"
)

// ClientKeys returns the registered P-256 public key (SPKI DER) of an active
// client. An unknown or inactive client is an error.
type ClientKeys interface {
	ClientPublicKey(clientID string) ([]byte, error)
}

// Authenticator identifies a request from its Authorization bearer assertion.
type Authenticator struct {
	db       *orm.DB
	keys     ClientKeys
	audience string
	notify   func(auth.SecurityEvent)
}

var (
	_ auth.Authenticator     = (*Authenticator)(nil)
	_ auth.RequestIdentifier = (*Authenticator)(nil)
)

// New builds the authenticator. audience is this server's identifier, e.g.
// "https://iam.velty.cl": assertions must name it in aud, and htu must be
// audience+path. notify may be nil.
func New(db *orm.DB, keys ClientKeys, audience string, notify func(auth.SecurityEvent)) (*Authenticator, error) {
	if audience == "" {
		return nil, fmt.Err(ErrMsgEmptyAudience)
	}
	return &Authenticator{db: db, keys: keys, audience: audience, notify: notify}, nil
}

func (a *Authenticator) Name() string { return name }

// Mount registers nothing: a client assertion rides on other routes.
func (a *Authenticator) Mount(router.Router) {}

// Migrate creates the table this package owns (deploy-time, like authority.Migrate).
func Migrate(conn ddl.Execer, ddlCompiler ddl.Compiler) error {
	sorted, err := ddl.TopologicalSort([]model.Model{&ClientAssertionJti{}})
	if err != nil {
		return err
	}
	return ddl.New(conn, ddlCompiler).Sync(sorted...)
}

func (a *Authenticator) reject(iss, reason string) (auth.Principal, bool) {
	if a.notify != nil {
		a.notify(auth.SecurityEvent{Type: auth.EventClientAssertionRejected, UserID: iss, Reason: reason, Timestamp: time.Now() / 1e9})
	}
	return auth.Principal{}, true
}

// IdentifyRequest: no bearer means "not this kind of request" (handled false).
// Any bearer is final: a failure is anonymous AND handled, so a valid session
// cookie riding along cannot rescue a bad assertion.
func (a *Authenticator) IdentifyRequest(ctx router.Context) (auth.Principal, bool) {
	token, ok := jwt.FromBearer(ctx.GetHeader("Authorization"))
	if !ok {
		return auth.Principal{}, false
	}
	iss, err := jwt.UnverifiedAssertionIssuer(token)
	if err != nil {
		return a.reject("", reasonMalformed)
	}
	key, err := a.keys.ClientPublicKey(iss)
	if err != nil {
		return a.reject(iss, reasonUnknownClient)
	}
	claims, outcome, err := jwt.VerifyClientAssertion(key, token)
	if err != nil || outcome == jwt.Forged {
		return a.reject(iss, reasonSignature)
	}
	if outcome == jwt.Expired {
		return a.reject(iss, reasonExpired)
	}
	if claims.Aud != a.audience {
		return a.reject(iss, reasonAudience)
	}
	if claims.Htm != ctx.Method() || claims.Htu != a.audience+ctx.Path() {
		return a.reject(iss, reasonBinding)
	}

	// Housekeeping: its failure only leaves old rows behind.
	a.db.Delete(&ClientAssertionJti{}, orm.Lt(ClientAssertionJti_.ExpiresAt, time.Now()/1e9))
	jti := ClientAssertionJti{Id: iss + jtiSeparator + claims.Jti, ExpiresAt: claims.Exp}
	if err := a.db.Create(&jti); err != nil { // duplicate primary key: replay
		return a.reject(iss, reasonReplay)
	}
	return auth.Principal{UserID: iss, Assurance: model.AssuranceSingleFactor}, true
}
