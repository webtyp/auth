package trustedip

import (
	"webtyp.com/auth"
	"webtyp.com/model"
)

// Devices is the register of trusted devices the app keeps (for example its staff module): which IP each person may
// sign in from, and how the first administrator's device is recorded.
type Devices interface {
	auth.TrustedIPStore
	RegisterFirstAdmin(userID, rut, name, ip string) error
}

// Mode is sign-in with a RUT from a device the app's register trusts, for a closed network such as a clinic. From
// the Internet its routes answer 404.
//
//	SignIn: []auth.Mode{trustedip.Mode{Devices: staffmanager.Definition}}
type Mode struct {
	Devices model.ModuleDefinition // the app module that is the register of trusted devices (implements Devices)
}

// Build makes the mode with the pieces of p: the register named by Devices, the rate limit, and the first-run
// setup that creates the first administrator from the device it is run on.
func (t Mode) Build(p auth.Ports) (auth.Authenticator, error) {
	if t.Devices.Name == "" {
		return nil, ErrNoDevices
	}
	if p.Built == nil || p.MakeAdmin == nil || p.HasAdmin == nil || p.Limiter == nil {
		return nil, ErrPortsIncomplete
	}
	built, err := p.Built(t.Devices)
	if err != nil {
		return nil, err
	}
	devices, ok := built.(Devices)
	if !ok {
		return nil, ErrNotDevices
	}
	create := func(rut, name, ip string) error {
		u, err := p.Identities.CreateUser("", name, "")
		if err != nil {
			return err
		}
		if err := RegisterRUT(p.Identities, u.Id, rut); err != nil {
			return err
		}
		if err := devices.RegisterFirstAdmin(u.Id, rut, name, ip); err != nil {
			return err
		}
		return p.MakeAdmin(u.Id)
	}
	return New(p.Identities, devices, p.Sessions, p.Report, p.TrustProxy,
		WithRateLimit(p.Limiter),
		WithFirstAdminSetup(p.HasAdmin, create)), nil
}

var _ auth.Mode = Mode{}
