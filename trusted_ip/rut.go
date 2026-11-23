package trustedip

import "webtyp.com/auth"

// RegisterRUT links a RUT to userID as their trusted_ip identity, so they can sign in with it from a trusted device.
// The RUT is checksum-validated; one RUT belongs to one person (auth.ErrRUTTaken).
//
//	err := trustedip.RegisterRUT(users, user.Id, "8.123.456-6")
func RegisterRUT(store auth.IdentityStore, userID, rut string) error {
	normalized, err := ValidateRUT(rut)
	if err != nil {
		return err
	}
	id, err := store.IdentityByProvider(auth.ProviderTrustedIP, normalized)
	if err == nil {
		if id.UserId != userID {
			return auth.ErrRUTTaken
		}
		return nil
	}
	if !auth.IsNotFound(err) {
		return err
	}
	return store.UpsertIdentity(userID, auth.ProviderTrustedIP, normalized, "")
}

// UnregisterRUT removes userID's RUT: they can no longer sign in with this mode. auth.ErrNotFound when they had none.
//
//	err := trustedip.UnregisterRUT(users, user.Id)
func UnregisterRUT(store auth.IdentityStore, userID string) error {
	return store.DeleteIdentity(userID, auth.ProviderTrustedIP)
}

// GiveSignIn creates the account a person signs in with by RUT (user + RUT identity), or returns the user that already
// has that RUT (auth.GivesSignIn). The app's staff module calls it when a professional is saved.
//
//	userID, err := authenticator.GiveSignIn("8.123.456-6", "Dra. Ana Rojas")
func (a *Authenticator) GiveSignIn(rut, name string) (string, error) {
	normalized, err := ValidateRUT(rut)
	if err != nil {
		return "", err
	}
	id, err := a.store.IdentityByProvider(auth.ProviderTrustedIP, normalized)
	if err == nil {
		return id.UserId, nil
	}
	if !auth.IsNotFound(err) {
		return "", err
	}
	u, err := a.store.CreateUser("", name, "")
	if err != nil {
		return "", err
	}
	if err := RegisterRUT(a.store, u.Id, normalized); err != nil {
		return "", err
	}
	return u.Id, nil
}

var _ auth.GivesSignIn = (*Authenticator)(nil)
