package authority

import (
	"webtyp.com/auth"
	"webtyp.com/crud"
	"webtyp.com/model"
	"webtyp.com/storage"
	"webtyp.com/time"
)

// Create es la regla de negocio de crear user: el correo no puede estar registrado (un usuario sin correo es válido: el
// personal LAN entra por RUT). El estado y la fecha de alta los pone el módulo.
func (p *User) Create(a crud.CurrentUser, tx crud.Tx, m *Module) (crud.RuleAnswer, error) {
	if p.Email != "" {
		_, found, err := firstRow(tx, func() model.Model { return &User{} }, storage.Eq("email", p.Email))
		if err != nil {
			return crud.RuleAnswer{}, err
		}
		if found {
			return crud.RuleAnswer{}, &model.FieldError{Field: "email", Err: auth.ErrEmailTaken}
		}
	}
	p.Status = "active"
	p.CreatedAt = time.NowUnix()
	return crud.ApplyAndPublish(), nil
}
