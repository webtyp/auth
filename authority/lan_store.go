package authority

import (
	"webtyp.com/auth"
	"webtyp.com/crud"
	"webtyp.com/model"
)

// lanStore guarda las identidades LAN usando las reglas de RegisterLAN y UnregisterLAN: crear registra el RUT del usuario,
// borrar quita la identidad y sus IP permitidas. Actualizar no existe. La clave de la fila es el id del usuario.
type lanStore struct{ m *Module }

func (s *lanStore) NewID() string { return "" } // la clave es el id del usuario: la envía quien llama

func (s *lanStore) Create(rec model.Model) error {
	lan := rec.(*LANIdentity)
	if err := s.m.RegisterLAN(lan.UserId, lan.Rut); err != nil {
		return err
	}
	identity, err := s.m.IdentityFor(lan.UserId, auth.ProviderTrustedIP)
	if err != nil {
		return err
	}
	lan.Rut = identity.ProviderId // el RUT normalizado
	return nil
}

func (s *lanStore) ReadOne(rec model.Model, id string) error {
	identity, err := s.m.IdentityFor(id, auth.ProviderTrustedIP)
	if err != nil {
		return asNotFound(err)
	}
	lan := rec.(*LANIdentity)
	lan.UserId, lan.Rut = id, identity.ProviderId
	return nil
}

func (s *lanStore) ReadAll(newRow func() model.Model, q crud.Query, onRow func(model.Model)) error {
	rows, err := allRows(s.m.users, func() model.Model { return &Identity{} }, func(r model.Model) string { return r.(*Identity).Id })
	if err != nil {
		return err
	}
	for _, r := range rows {
		if id := r.(*Identity); id.Provider == auth.ProviderTrustedIP {
			lan := newRow().(*LANIdentity)
			lan.UserId, lan.Rut = id.UserId, id.ProviderId
			onRow(lan)
		}
	}
	return nil
}

func (s *lanStore) UpdateFields(rec model.Model, id string, fields []string) error {
	return model.NotFound("lan identities are not updated: register again")
}

func (s *lanStore) Delete(rec model.Model, id string) error {
	return asNotFound(s.m.UnregisterLAN(id))
}

// asNotFound hace que el «no existe» de auth se vea como tal para crud (model.ErrorNotFound).
func asNotFound(err error) error {
	if err != nil && auth.IsNotFound(err) {
		return model.NotFound("lan identity not found")
	}
	return err
}
