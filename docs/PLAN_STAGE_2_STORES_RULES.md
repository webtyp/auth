← [Stage 1](PLAN_STAGE_1_MOVE_MODELS.md) | Next → [Stage 3](PLAN_STAGE_3_METHODS_IMPORTERS.md)

# Stage 2 — stores, `lanStore`, rules, the `/me` route

## 2.1 `authority/store.go` and `authority/rows.go` (new), written exactly

```go
package authority

import (
	"webtyp.com/crud"
	"webtyp.com/model"
	"webtyp.com/orm"
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
		if len(page) < crud.MaxPage {
			return rows, nil
		}
		after = key(page[len(page)-1])
	}
}

// notFound cambia el error «no existe» de un repositorio por `missing` y deja pasar cualquier otro error.
func notFound(err error, missing error) error {
	if model.KindOf(err) == model.ErrorNotFound {
		return missing
	}
	return err
}

var _ = orm.GlobalStore // los usuarios se guardan con orm.GlobalStore(db, ids): ver New
```
In `authority/module.go`: `Module` gains `users *orm.Store`, built in `New` as `m.users = orm.GlobalStore(db, cfg.IDs)` (before `return`). `m.db` stays: sessions, identities, LAN IPs and OAuth states are written by the module with it, as today. Drop the `var _ = orm.GlobalStore` line from `rows.go` once `module.go` imports `orm` (it already does).

## 2.2 `authority/lan_store.go` (new): the store of `LANIdentity`

A `crud.Store` over `RegisterLAN`, `UnregisterLAN` and `IdentityFor`. The row id is the `user_id`. Written exactly:

```go
package authority

import (
	"webtyp.com/auth"
	"webtyp.com/crud"
	"webtyp.com/model"
)

// lanStore guarda las identidades LAN usando las reglas de RegisterLAN y UnregisterLAN: crear registra el RUT del usuario,
// borrar quita la identidad y sus IP permitidas. Actualizar no existe.
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
		return notFound(err, crud.ErrNotFound)
	}
	lan := rec.(*LANIdentity)
	lan.UserId, lan.Rut = id, identity.ProviderId
	return nil
}

func (s *lanStore) ReadAll(newRow func() model.Model, q crud.Query, onRow func(model.Model)) error {
	rows, err := allRows(s.m.db, func() model.Model { return &Identity{} }, func(r model.Model) string { return r.(*Identity).Id })
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

func (s *lanStore) UpdateFields(rec model.Model, id string, fields []string) error { return crud.ErrNotFound }

func (s *lanStore) Delete(rec model.Model, id string) error {
	return notFound(s.m.UnregisterLAN(id), crud.ErrNotFound)
}
```
Do not leave it as written if the compiler disagrees: `crud.Store` is `Tx + NewID() string` (`go doc webtyp.com/crud Store`); `*orm.DB` is not a `crud.Tx`, so the `allRows(s.m.db, …)` call in `ReadAll` must be `allRows(s.m.rows, …)` where `m.rows` is a second store `orm.GlobalStore(db, ids)` (the same store as `m.users`; reuse `m.users`: `allRows(s.m.users, …)`). `auth.ErrNotFound` is `auth`'s sentinel; `crud.ErrNotFound` is what `crud` expects from a store for «absent»: if `crud.ErrNotFound` does not exist, return an error whose `model.KindOf` is `model.ErrorNotFound` (`auth.ErrNotFound` is a `model.NotFound`? check `go doc`; if not, wrap it with `model.NotFound`).

## 2.3 The rule files (keep each generated signature; Spanish comment on top; imports `webtyp.com/crud`, `webtyp.com/model`, `webtyp.com/storage`, `webtyp.com/time`, `webtyp.com/auth`)

```go
// Create es la regla de negocio de crear user: el correo no puede estar registrado (un usuario sin correo es válido: el personal LAN entra por RUT).
func (p *User) Create(a crud.CurrentUser, tx crud.Tx, m *Module) (crud.RuleAnswer, error) {
	if p.Email != "" {
		_, found, err := firstRow(tx, func() model.Model { return &User{} }, storage.Eq(User_.Email, p.Email))
		if err != nil {
			return 0, err
		}
		if found {
			return 0, &model.FieldError{Field: User_.Email, Err: auth.ErrEmailTaken}
		}
	}
	p.Status = "active"
	p.CreatedAt = time.NowUnix()
	return crud.ApplyAndPublish, nil
}

// Update es la regla de negocio de actualizar user: solo se cambian name y phone (lo que escribía updateUser).
func (next *User) Update(a crud.CurrentUser, tx crud.Tx, old *User, fields []string, m *Module) (crud.RuleAnswer, error) {
	for _, f := range fields {
		if f != User_.Name && f != User_.Phone {
			return 0, &model.FieldError{Field: f, Err: auth.ErrNotEditable}
		}
	}
	m.ucache.Delete(old.Id)
	return crud.ApplyAndPublish, nil
}

// Delete es la regla de negocio de borrar user: se olvida del caché de usuarios. El receptor es la fila guardada.
func (p *User) Delete(a crud.CurrentUser, tx crud.Tx, m *Module) (crud.RuleAnswer, error) {
	m.ucache.Delete(p.Id)
	return crud.ApplyAndPublish, nil
}
```
`rule_user_read.go` is a `Search` (a table `Read` declared `AddMyBusinessRule`): `func (p *User) Search(a crud.CurrentUser, filter *User, text string, m *Module) ([]storage.Condition, error)` answers `[]storage.Condition{storage.Like(User_.Name, "%"+text+"%")}` when `text != ""`, else `nil, nil`. Add to the root `user.go` the one new error `ErrNotEditable domainError = "field not editable"` next to the others (a `domainError` is a `model.Invalid`? if `model.KindOf` does not say Invalid, declare it `model.Invalid` instead, as `ErrFieldNotEditable` is in the other modules).

## 2.4 The `/me` route (`authority/mount.go`)

`/me` is the authenticated caller's profile, not an entity operation. In `MountAPI` add, after the logout route and written in the same style (an authenticated route is one WITHOUT `.Public()`):

```go
	r.Get(auth.PathMe, m.handleMe)
```
Add `PathMe = "/me"` next to `PathLogout` in the root `user.go`, and rename the old `opMe` handler (`authority/ops.go`) to `handleMe` keeping its body. Delete `authority/ops.go` (the other handlers are replaced by the rules), `authority/ops_lan.go` and `authority/crud.go` (the `userCRUD`/`lanipCRUD` hand handlers) — **after** moving `handleMe` out of `ops.go` into `mount.go`. `LANIP` has no `crud` operation any more: it was only reachable through `lanipCRUD`; `AssignLANIP`/`RevokeLANIP` stay as methods.

Commit and push; **open the pull request now**.
