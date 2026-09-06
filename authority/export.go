package authority

import "webtyp.com/auth"

func (m *Module) GetUserByEmail(email string) (auth.User, error) {
	return getUserByEmail(m.db, m.ucache, email)
}
