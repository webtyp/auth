package passkey

import (
	"webtyp.com/auth"
	"webtyp.com/base64"
	"webtyp.com/orm"
	"webtyp.com/router"
	"webtyp.com/webauthn/server"
)

var _ auth.Authenticator = (*Module)(nil)

// Mount registers the passkey routes.
func (m *Module) Mount(r router.Router) {
	r.Post(PathRegisterOptions, m.registerOptions).Authenticated()
	r.Post(PathRegister, m.register).Authenticated()
	r.Post(PathVerifyOptions, m.verifyOptions).Authenticated()
	r.Post(PathVerify, m.verify).Authenticated()
	r.Get(PathList, m.list).Authenticated().RequiresMFA()
	r.Post(PathDelete, m.remove).Authenticated().RequiresMFA()
}

func (m *Module) registerOptions(ctx router.Context) {
	if !m.enrollmentAllowed(ctx) {
		return
	}
	userID := ctx.UserID()
	existing, err := m.credentialsOf(userID)
	if err != nil {
		ctx.WriteStatus(500)
		return
	}
	challenge, err := m.newChallenge(userID, purposeRegister)
	if err != nil {
		ctx.WriteStatus(500)
		return
	}
	ids := make([]string, len(existing))
	for i, c := range existing {
		ids[i] = c.Id
	}
	ctx.Encode(&registerOptions{
		Challenge:          base64.URLEncode(challenge),
		RPID:               m.rp.ID,
		UserID:             base64.URLEncode([]byte(userID)),
		UserName:           userID,
		ExcludeCredentials: ids,
	})
}

func (m *Module) register(ctx router.Context) {
	if !m.enrollmentAllowed(ctx) {
		return
	}
	userID := ctx.UserID()
	challenge, ok := m.consumeChallenge(userID, purposeRegister)
	if !ok {
		m.reject(ctx, 401, reasonChallenge)
		return
	}
	reg, err := m.rp.VerifyRegistration(string(ctx.Body()), challenge)
	if err != nil {
		m.reject(ctx, 401, err.Error())
		return
	}
	t := now()
	cred := PasskeyCredential{
		Id:        base64.URLEncode(reg.CredentialID),
		UserId:    userID,
		PublicKey: base64.URLEncode(reg.PublicKey),
		SignCount: int64(reg.SignCount),
		CreatedAt: t,
	}
	if err := m.db.Create(&cred); err != nil {
		ctx.WriteStatus(500)
		return
	}
	m.sessions.Notify(auth.SecurityEvent{Type: auth.EventPasskeyRegistered, UserID: userID})
	ctx.WriteStatus(204)
}

func (m *Module) verifyOptions(ctx router.Context) {
	userID := ctx.UserID()
	existing, err := m.credentialsOf(userID)
	if err != nil {
		ctx.WriteStatus(500)
		return
	}
	if len(existing) == 0 {
		ctx.WriteStatus(404)
		return
	}
	challenge, err := m.newChallenge(userID, purposeVerify)
	if err != nil {
		ctx.WriteStatus(500)
		return
	}
	ids := make([]string, len(existing))
	for i, c := range existing {
		ids[i] = c.Id
	}
	ctx.Encode(&verifyOptions{
		Challenge:        base64.URLEncode(challenge),
		RPID:             m.rp.ID,
		AllowCredentials: ids,
	})
}

func (m *Module) verify(ctx router.Context) {
	userID := ctx.UserID()
	raw := string(ctx.Body())
	rawID, err := server.UnverifiedCredentialID(raw)
	if err != nil {
		m.reject(ctx, 401, err.Error())
		return
	}
	cred, found := m.credential(base64.URLEncode(rawID))
	if !found || cred.UserId != userID {
		m.reject(ctx, 403, reasonForeignCredential)
		return
	}
	challenge, ok := m.consumeChallenge(userID, purposeVerify)
	if !ok {
		m.reject(ctx, 401, reasonChallenge)
		return
	}
	pub, err := base64.URLDecode(cred.PublicKey)
	if err != nil {
		ctx.WriteStatus(500)
		return
	}
	count, err := m.rp.VerifyAssertion(raw, challenge, server.StoredCredential{
		ID: rawID, PublicKey: pub, SignCount: uint32(cred.SignCount),
	})
	if err != nil {
		m.reject(ctx, 401, err.Error())
		return
	}
	cred.SignCount = int64(count)
	cred.LastUsedAt = now()
	if err := m.db.Update(cred, orm.Eq(PasskeyCredential_.Id, cred.Id)); err != nil {
		ctx.WriteStatus(500)
		return
	}
	if err := m.sessions.IssueStepUpSession(ctx, userID); err != nil {
		ctx.WriteStatus(500)
		return
	}
	m.sessions.Notify(auth.SecurityEvent{Type: auth.EventPasskeyVerified, UserID: userID})
	ctx.WriteStatus(204)
}

func (m *Module) list(ctx router.Context) {
	rows, err := m.credentialsOf(ctx.UserID())
	if err != nil {
		ctx.WriteStatus(500)
		return
	}
	ctx.Encode(&credentialList{items: rows})
}

// remove deletes one of the caller's credentials; the body is its id.
func (m *Module) remove(ctx router.Context) {
	userID := ctx.UserID()
	cred, found := m.credential(string(ctx.Body()))
	if !found || cred.UserId != userID {
		ctx.WriteStatus(404)
		return
	}
	if err := m.db.Delete(cred, orm.Eq(PasskeyCredential_.Id, cred.Id)); err != nil {
		ctx.WriteStatus(500)
		return
	}
	m.sessions.Notify(auth.SecurityEvent{Type: auth.EventPasskeyDeleted, UserID: userID})
	ctx.WriteStatus(204)
}
