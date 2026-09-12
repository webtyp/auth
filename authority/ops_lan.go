package authority

import (
	"webtyp.com/router"
	"webtyp.com/auth"
)

func (m *Module) opRegisterLAN(ctx router.Context) {
	var args auth.RegisterLANArgs
	if err := ctx.Decode(&args); err != nil {
		ctx.WriteStatus(400)
		return
	}
	if err := m.RegisterLAN(args.UserId, args.Rut); err != nil {
		switch err {
		case auth.ErrInvalidRUT, auth.ErrRUTTaken:
			ctx.WriteStatus(409)
			ctx.Write([]byte(err.Error()))
		default:
			ctx.WriteStatus(500)
		}
		return
	}
	identity, err := m.IdentityFor(args.UserId, auth.ProviderTrustedIP)
	if err != nil {
		ctx.WriteStatus(500)
		return
	}
	lan := auth.LANIdentity{UserId: args.UserId, Rut: identity.ProviderId}
	if err := ctx.Encode(&lan); err != nil {
		ctx.WriteStatus(500)
	}
}

func (m *Module) opUnregisterLAN(ctx router.Context) {
	var args auth.LANUserArgs
	if err := ctx.Decode(&args); err != nil {
		ctx.WriteStatus(400)
		return
	}
	if err := m.UnregisterLAN(args.UserId); err != nil {
		if err == auth.ErrNotFound {
			ctx.WriteStatus(404)
			return
		}
		ctx.WriteStatus(500)
		return
	}
	ctx.WriteStatus(200)
}

func (m *Module) opGetLAN(ctx router.Context) {
	var args auth.LANUserArgs
	if err := ctx.Decode(&args); err != nil {
		ctx.WriteStatus(400)
		return
	}
	identity, err := m.IdentityFor(args.UserId, auth.ProviderTrustedIP)
	if err != nil {
		if err == auth.ErrNotFound {
			ctx.WriteStatus(404)
			return
		}
		ctx.WriteStatus(500)
		return
	}
	lan := auth.LANIdentity{UserId: args.UserId, Rut: identity.ProviderId}
	if err := ctx.Encode(&lan); err != nil {
		ctx.WriteStatus(500)
	}
}
