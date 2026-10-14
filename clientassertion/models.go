package clientassertion

import "webtyp.com/model"

// ClientAssertionJtiModel remembers an assertion's jti until it expires, so a
// captured assertion cannot be replayed.
var ClientAssertionJtiModel = model.Definition{
	Name: "client_assertion_jti",
	Fields: model.Fields{
		{Name: "id", Type: model.Text(), DB: &model.FieldDB{PK: true}}, // iss + ":" + jti
		{Name: "expires_at", Type: model.Int()},
	},
}
