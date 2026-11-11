package authority

import (
	"webtyp.com/auth"
	"webtyp.com/crud"
	"webtyp.com/model"
)

// Update es la regla de negocio de actualizar user: old es la fila guardada y el receptor trae solo los campos enviados
// (fields). Solo se cambian name y phone (lo que escribía updateUser); el caché de usuarios se olvida del usuario.
func (next *User) Update(a crud.CurrentUser, tx crud.Tx, old *User, fields []string, m *Module) (crud.RuleAnswer, error) {
	for _, f := range fields {
		if f != "name" && f != "phone" {
			return crud.RuleAnswer{}, &model.FieldError{Field: f, Err: auth.ErrNotEditable}
		}
	}
	m.ucache.Delete(old.Id)
	return crud.ApplyAndPublish(), nil
}
