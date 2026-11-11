package authority

import (
	"webtyp.com/orm"
	"webtyp.com/time"
	trustedip "webtyp.com/auth/trusted_ip"

	"webtyp.com/router"
	"webtyp.com/auth"
)

// LoginLAN verifies a RUT + the caller's IP directly (no HTTP) — used by tests
// and any admin flow. Mirrors exactly what trusted_ip's Mount handler does,
// using the same ValidateRUT algorithm — see §7's doc comment on ValidateRUT.
func (m *Module) LoginLAN(rut string, ctx router.Context) (auth.User, error) {
	normalized, err := trustedip.ValidateRUT(rut)
	if err != nil {
		return auth.User{}, auth.ErrInvalidRUT
	}
	identity, err := m.IdentityByProvider(auth.ProviderTrustedIP, normalized)
	if err != nil {
		return auth.User{}, auth.ErrInvalidCredentials
	}
	u, err := m.UserByID(identity.UserId)
	if err != nil {
		return auth.User{}, auth.ErrInvalidCredentials
	}
	if u.Status == "suspended" {
		return auth.User{}, auth.ErrSuspended
	}
	ip := auth.ClientIP(ctx, m.config.TrustProxy)
	if !m.IsTrustedIP(u.Id, ip) {
		return auth.User{}, auth.ErrInvalidCredentials
	}
	return u, nil
}

// RegisterLAN links a RUT to userID as their trusted_ip identity.
func (m *Module) RegisterLAN(userID, rut string) error {
	normalized, err := trustedip.ValidateRUT(rut)
	if err != nil {
		return auth.ErrInvalidRUT
	}
	id, err := m.IdentityByProvider(auth.ProviderTrustedIP, normalized)
	if err == nil {
		if id.UserId != userID {
			return auth.ErrRUTTaken
		}
		return nil
	} else if !auth.IsNotFound(err) {
		return err
	}
	return m.UpsertIdentity(userID, auth.ProviderTrustedIP, normalized, "")
}

// UnregisterLAN removes userID's trusted_ip identity and all their allowed IPs.
func (m *Module) UnregisterLAN(userID string) error {
	_, err := m.IdentityFor(userID, auth.ProviderTrustedIP)
	if auth.IsNotFound(err) {
		return auth.ErrNotFound
	}
	if err != nil {
		return err
	}
	qb := m.db.Query(&LANIP{}).Where(LANIP_.UserId).Eq(userID)
	ips, _ := ReadAllLANIP(qb)
	for _, ip := range ips {
		m.db.Delete(ip, orm.Eq(LANIP_.Id, ip.Id))
	}
	qbId := m.db.Query(&Identity{}).Where(Identity_.UserId).Eq(userID).Where(Identity_.Provider).Eq(auth.ProviderTrustedIP)
	ids, _ := ReadAllIdentity(qbId)
	for _, id := range ids {
		m.db.Delete(id, orm.Eq(Identity_.Id, id.Id))
	}
	return nil
}

func (m *Module) AssignLANIP(userID, ip, label string) error {
	qb := m.db.Query(&LANIP{}).Where(LANIP_.Ip).Eq(ip)
	results, err := ReadAllLANIP(qb)
	if err != nil {
		return err
	}
	if len(results) > 0 {
		return auth.ErrIPTaken
	}
	i := &LANIP{Id: m.ids.NewID(), UserId: userID, Ip: ip, Label: label, CreatedAt: time.NowUnix()}
	return m.db.Create(i)
}

func (m *Module) RevokeLANIP(userID, ip string) error {
	qb := m.db.Query(&LANIP{}).Where(LANIP_.UserId).Eq(userID).Where(LANIP_.Ip).Eq(ip)
	results, err := ReadAllLANIP(qb)
	if err != nil {
		return err
	}
	if len(results) == 0 {
		return auth.ErrNotFound
	}
	return m.db.Delete(results[0], orm.Eq(LANIP_.Id, results[0].Id))
}

func (m *Module) GetLANIPs(userID string) ([]LANIP, error) {
	qb := m.db.Query(&LANIP{}).Where(LANIP_.UserId).Eq(userID).OrderBy(LANIP_.CreatedAt).Asc()
	results, err := ReadAllLANIP(qb)
	if err != nil {
		return nil, err
	}
	ips := make([]LANIP, 0, len(results))
	for _, r := range results {
		ips = append(ips, *r)
	}
	return ips, nil
}

// checkLANIP is used by both LoginLAN above and Module.IsTrustedIP (ports.go) —
// the TrustedIPStore port implementation.
func checkLANIP(db *orm.DB, userID, ip string) error {
	qb := db.Query(&LANIP{}).Where(LANIP_.UserId).Eq(userID).Where(LANIP_.Ip).Eq(ip)
	results, err := ReadAllLANIP(qb)
	if err != nil || len(results) == 0 {
		return auth.ErrInvalidCredentials
	}
	return nil
}
