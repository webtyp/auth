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
