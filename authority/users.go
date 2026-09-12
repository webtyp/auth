package authority

import (
	"webtyp.com/fmt"
	"webtyp.com/time"

	"webtyp.com/model"
	"webtyp.com/orm"
	"webtyp.com/storage"
	"webtyp.com/auth"
)

func createUser(db *orm.DB, ids model.IDGenerator, email, name, phone string) (auth.User, error) {
	id := ids.NewID()
	now := time.Now() / 1e9

	if email == "" {
		fields := []string{"id", "name", "phone", "status", "created_at"}
		values := []any{id, name, phone, "active", now}
		q := storage.Query{
			Action:  storage.ActionCreate,
			Table:   "user",
			Columns: fields,
			Values:  values,
		}
		conn := db.RawConn()
		plan, err := conn.Compile(q, &auth.User{})
		if err != nil {
			return auth.User{}, err
		}
		if err := conn.Exec(plan.Query, plan.Args...); err != nil {
			return auth.User{}, err
		}
		return auth.User{
			Id:        id,
			Name:      name,
			Phone:     phone,
			Status:    "active",
			CreatedAt: now,
		}, nil
	}

	newUser := auth.User{
		Id:        id,
		Email:     email,
		Name:      name,
		Phone:     phone,
		Status:    "active",
		CreatedAt: now,
	}

	if err := db.Create(&newUser); err != nil {
		if isUniqueViolation(err) {
			return auth.User{}, auth.ErrEmailTaken
		}
		return auth.User{}, err
	}
	return newUser, nil
}

func (m *Module) GetUser(id string) (auth.User, error) {
	return getUser(m.db, m.ucache, id)
}

func getUser(db *orm.DB, cache *userCache, id string) (auth.User, error) {
	if cache != nil {
		if cached, ok := cache.Get(id); ok {
			return *cached, nil
		}
	}

	qb := db.Query(&auth.User{}).Where(auth.User_.Id).Eq(id)
	results, err := auth.ReadAllUser(qb)
	if err != nil {
		return auth.User{}, err
	}
	if len(results) == 0 {
		return auth.User{}, auth.ErrNotFound
	}
	u := results[0]

	if cache != nil {
		cache.Set(u.Id, u)
	}
	return *u, nil
}

func getUserByEmail(db *orm.DB, cache *userCache, email string) (auth.User, error) {
	qb := db.Query(&auth.User{}).Where(auth.User_.Email).Eq(email)
	results, err := auth.ReadAllUser(qb)
	if err != nil {
		return auth.User{}, err
	}
	if len(results) == 0 {
		return auth.User{}, auth.ErrNotFound
	}
	u := results[0]

	if cache != nil {
		if cached, ok := cache.Get(u.Id); ok {
			return *cached, nil
		}
		cache.Set(u.Id, u)
	}
	return *u, nil
}

func updateUser(db *orm.DB, cache *userCache, id, name, phone string) error {
	if cache != nil {
		cache.Delete(id)
	}
	qb := db.Query(&auth.User{}).Where(auth.User_.Id).Eq(id)
	results, err := auth.ReadAllUser(qb)
	if err != nil || len(results) == 0 {
		return auth.ErrNotFound
	}
	u := results[0]
	u.Name = name
	u.Phone = phone
	return db.Update(u, orm.Eq(auth.User_.Id, u.Id))
}

func updateUserAvatar(db *orm.DB, cache *userCache, id, avatar string) error {
	if cache != nil {
		cache.Delete(id)
	}
	qb := db.Query(&auth.User{}).Where(auth.User_.Id).Eq(id)
	results, err := auth.ReadAllUser(qb)
	if err != nil || len(results) == 0 {
		return auth.ErrNotFound
	}
	u := results[0]
	u.Avatar = avatar
	return db.Update(u, orm.Eq(auth.User_.Id, u.Id))
}

func suspendUser(db *orm.DB, cache *userCache, id string) error {
	if cache != nil {
		cache.Delete(id)
	}
	qb := db.Query(&auth.User{}).Where(auth.User_.Id).Eq(id)
	results, err := auth.ReadAllUser(qb)
	if err != nil || len(results) == 0 {
		return auth.ErrNotFound
	}
	u := results[0]
	u.Status = "suspended"
	return db.Update(u, orm.Eq(auth.User_.Id, u.Id))
}

func reactivateUser(db *orm.DB, cache *userCache, id string) error {
	if cache != nil {
		cache.Delete(id)
	}
	qb := db.Query(&auth.User{}).Where(auth.User_.Id).Eq(id)
	results, err := auth.ReadAllUser(qb)
	if err != nil || len(results) == 0 {
		return auth.ErrNotFound
	}
	u := results[0]
	u.Status = "active"
	return db.Update(u, orm.Eq(auth.User_.Id, u.Id))
}

func listUsers(db *orm.DB) ([]auth.User, error) {
	qb := db.Query(&auth.User{})
	users, err := auth.ReadAllUser(qb)
	if err != nil {
		return nil, err
	}
	res := make([]auth.User, len(users))
	for i, u := range users {
		res[i] = *u
	}
	return res, nil
}

func deleteUser(db *orm.DB, cache *userCache, id string) error {
	if cache != nil {
		cache.Delete(id)
	}
	qb := db.Query(&auth.User{}).Where(auth.User_.Id).Eq(id)
	results, err := auth.ReadAllUser(qb)
	if err != nil || len(results) == 0 {
		return auth.ErrNotFound
	}
	u := results[0]
	return db.Delete(u, orm.Eq(auth.User_.Id, u.Id))
}

func isUniqueViolation(err error) bool {
	return fmt.Contains(err.Error(), "UNIQUE constraint failed") ||
		fmt.Contains(err.Error(), "constraint: unique") ||
		fmt.Contains(err.Error(), "duplicate key")
}
