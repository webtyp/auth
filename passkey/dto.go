package passkey

import "webtyp.com/model"

// Reasons recorded in EventPasskeyRejected.
const (
	reasonChallenge         = "passkey: challenge missing, expired or already used"
	reasonForeignCredential = "passkey: credential does not belong to this user"
)

type registerOptions struct {
	Challenge          string
	RPID               string
	UserID             string
	UserName           string
	ExcludeCredentials []string
}

func (o *registerOptions) IsNil() bool { return o == nil }
func (o *registerOptions) EncodeFields(w model.FieldWriter) {
	w.String("challenge", o.Challenge)
	w.String("rpId", o.RPID)
	w.String("userId", o.UserID)
	w.String("userName", o.UserName)
	writeStrings(w, "excludeCredentials", o.ExcludeCredentials)
}

type verifyOptions struct {
	Challenge        string
	RPID             string
	AllowCredentials []string
}

func (o *verifyOptions) IsNil() bool { return o == nil }
func (o *verifyOptions) EncodeFields(w model.FieldWriter) {
	w.String("challenge", o.Challenge)
	w.String("rpId", o.RPID)
	writeStrings(w, "allowCredentials", o.AllowCredentials)
}

func writeStrings(w model.FieldWriter, field string, vals []string) {
	a := w.Array(field, len(vals))
	for _, v := range vals {
		a.String(v)
	}
	a.Close()
}

// credentialList is the PathList body: id, created and last used of each credential.
type credentialList struct{ items PasskeyCredentialList }

func (l *credentialList) IsNil() bool { return l == nil }
func (l *credentialList) EncodeFields(w model.FieldWriter) {
	a := w.Array("credentials", len(l.items))
	for _, c := range l.items {
		a.Object(&credentialView{c})
	}
	a.Close()
}

type credentialView struct{ c *PasskeyCredential }

func (v *credentialView) IsNil() bool { return v == nil }
func (v *credentialView) EncodeFields(w model.FieldWriter) {
	w.String("id", v.c.Id)
	w.Int("created_at", int64(v.c.CreatedAt))
	w.Int("last_used_at", int64(v.c.LastUsedAt))
}
