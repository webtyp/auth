package authority

import (
	"webtyp.com/crud"
	"webtyp.com/storage"
)

// Search traduce el texto que escribió la persona en las condiciones que buscan user: por nombre. Sin texto no filtra.
func (p *User) Search(a crud.CurrentUser, filter *User, text string, m *Module) ([]storage.Condition, error) {
	if text == "" {
		return nil, nil
	}
	return []storage.Condition{storage.Like("name", "%"+text+"%")}, nil
}
