package passkey

import "webtyp.com/model"

// PasskeyCredentialModel is one enrolled WebAuthn credential of a user.
var PasskeyCredentialModel = model.Definition{
	Name: "passkey_credential",
	Fields: model.Fields{
		{Name: "id", Type: model.Text(), DB: &model.FieldDB{PK: true}}, // base64url credential id
		{Name: "user_id", Type: model.Text()},
		{Name: "public_key", Type: model.Text()}, // base64url SPKI DER
		{Name: "sign_count", Type: model.Int()},
		{Name: "created_at", Type: model.UnixTime()},
		{Name: "last_used_at", Type: model.UnixTime()},
	},
}

// PasskeyChallengeModel is a single-use challenge issued to a user.
var PasskeyChallengeModel = model.Definition{
	Name: "passkey_challenge",
	Fields: model.Fields{
		{Name: "id", Type: model.Text(), DB: &model.FieldDB{PK: true}}, // base64url challenge
		{Name: "user_id", Type: model.Text()},
		{Name: "purpose", Type: model.Text()},
		{Name: "expires_at", Type: model.UnixTime()},
	},
}
