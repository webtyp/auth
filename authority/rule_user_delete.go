package authority

import "webtyp.com/crud"

// Delete es la regla de negocio de borrar user: el módulo se olvida del usuario en el caché. El receptor es la fila guardada.
func (p *User) Delete(a crud.CurrentUser, tx crud.Tx, m *Module) (crud.RuleAnswer, error) {
	m.ucache.Delete(p.Id)
	return crud.ApplyAndPublish(), nil
}
