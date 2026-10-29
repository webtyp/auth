package passkey

import "webtyp.com/model"

// Reasons recorded in EventPasskeyRejected.
const (
	reasonChallenge         = "passkey: challenge missing, expired or already used"
	reasonForeignCredential = "passkey: credential does not belong to this user"
)

type RegisterOptions struct {
	Challenge          string
	RPID               string
	UserID             string
	UserName           string
	ExcludeCredentials []string
}

func (o *RegisterOptions) IsNil() bool { return o == nil }
func (o *RegisterOptions) EncodeFields(w model.FieldWriter) {
	w.String("challenge", o.Challenge)
	w.String("rpId", o.RPID)
	w.String("userId", o.UserID)
	w.String("userName", o.UserName)
	writeStrings(w, "excludeCredentials", o.ExcludeCredentials)
}
func (o *RegisterOptions) DecodeFields(r model.FieldReader) {
	o.Challenge, _ = r.String("challenge")
	o.RPID, _ = r.String("rpId")
	o.UserID, _ = r.String("userId")
	o.UserName, _ = r.String("userName")
	o.ExcludeCredentials = readStrings(r, "excludeCredentials")
}

type VerifyOptions struct {
	Challenge        string
	RPID             string
	AllowCredentials []string
}

func (o *VerifyOptions) IsNil() bool { return o == nil }
func (o *VerifyOptions) EncodeFields(w model.FieldWriter) {
	w.String("challenge", o.Challenge)
	w.String("rpId", o.RPID)
	writeStrings(w, "allowCredentials", o.AllowCredentials)
}
func (o *VerifyOptions) DecodeFields(r model.FieldReader) {
	o.Challenge, _ = r.String("challenge")
	o.RPID, _ = r.String("rpId")
	o.AllowCredentials = readStrings(r, "allowCredentials")
}

func readStrings(r model.FieldReader, field string) []string {
	a, _ := r.Array(field)
	if a == nil {
		return nil
	}
	vals := make([]string, a.Len())
	for i := 0; i < a.Len(); i++ {
		vals[i] = a.String(i)
	}
	return vals
}

func writeStrings(w model.FieldWriter, field string, vals []string) {
	a := w.Array(field, len(vals))
	for _, v := range vals {
		a.String(v)
	}
}

// credentialList is the PathList body: id, created and last used of each credential.
type credentialList struct{ items PasskeyCredentialList }

func (l *credentialList) IsNil() bool { return l == nil }
func (l *credentialList) EncodeFields(w model.FieldWriter) {
	a := w.Array("credentials", len(l.items))
	for _, c := range l.items {
		a.Object(&credentialView{c})
	}
}

type credentialView struct{ c *PasskeyCredential }

func (v *credentialView) IsNil() bool { return v == nil }
func (v *credentialView) EncodeFields(w model.FieldWriter) {
	w.String("id", v.c.Id)
	w.Int("created_at", int64(v.c.CreatedAt))
	w.Int("last_used_at", int64(v.c.LastUsedAt))
}
