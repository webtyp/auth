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

// StoreLANIdentity es el repositorio de las identidades LAN: no es una tabla, es una proyección de las identidades de
// proveedor trusted_ip.
//
// Ejemplo: store := m.StoreLANIdentity()
func (m *Module) StoreLANIdentity() crud.Store { return &lanStore{m: m} }

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

// allRows responde todas las filas que cumplen conds, paginando por id (una lectura trae como máximo crud.MaxPage).
func allRows(tx crud.Tx, newRow func() model.Model, key func(model.Model) string, conds ...storage.Condition) ([]model.Model, error) {
	var rows []model.Model
	after := ""
	for {
		var page []model.Model
		err := tx.ReadAll(newRow, crud.Query{Conditions: conds, After: after, Limit: crud.MaxPage}, func(r model.Model) { page = append(page, r) })
		if err != nil {
			return nil, err
		}
		rows = append(rows, page...)
		if int64(len(page)) < crud.MaxPage {
			return rows, nil
		}
		after = key(page[len(page)-1])
	}
}

// notFound cambia el error «no existe» de un repositorio por missing y deja pasar cualquier otro error.
func notFound(err error, missing error) error {
	if err != nil && model.KindOf(err) == model.ErrorNotFound {
		return missing
	}
	return err
}
