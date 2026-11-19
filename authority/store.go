package authority

import (
	"webtyp.com/crud"
	"webtyp.com/model"
	"webtyp.com/storage"
)

// StoreUser es el repositorio de los usuarios (sin tenant: los usuarios son globales).
//
// Ejemplo: store := m.StoreUser()
func (m *Module) StoreUser() crud.Store { return m.users }

// firstRow responde la primera fila que cumple conds y si existe alguna.
func firstRow(tx crud.Tx, newRow func() model.Model, conds ...storage.Condition) (model.Model, bool, error) {
	var first model.Model
	err := tx.ReadAll(newRow, crud.Query{Conditions: conds, Limit: 1}, func(r model.Model) {
		if first == nil {
			first = r
		}
	})
	return first, first != nil, err
}
