package emailpassword

import "webtyp.com/auth"

// minPasswordLength is the shortest password accepted.
const minPasswordLength = 8

// SetPassword hashes password and stores it as userID's email+password credential. validate, when not nil, may refuse
// the password first (for example a list of leaked passwords).
//
//	err := emailpassword.SetPassword(users, user.Id, "a-long-secret", nil)
func SetPassword(store auth.IdentityStore, userID, password string, validate func(password string) error) error {
	if len(password) < minPasswordLength {
		return auth.ErrWeakPassword
	}
	if validate != nil {
		if err := validate(password); err != nil {
			return err
		}
	}
	hash, err := HashPassword(password, DefaultHashCost)
	if err != nil {
		return err
	}
	return store.UpsertIdentity(userID, Provider, hash, "")
}

// CheckPassword checks password against userID's stored hash; auth.ErrInvalidCredentials when it does not match or
// they have none.
//
//	err := emailpassword.CheckPassword(users, user.Id, typed)
func CheckPassword(store auth.IdentityStore, userID, password string) error {
	identity, err := store.IdentityFor(userID, Provider)
	if err != nil {
		DummyCompare(password, DefaultHashCost)
		return auth.ErrInvalidCredentials
	}
	return VerifyPassword(identity.ProviderId, password)
}
