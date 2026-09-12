//go:build !wasm

package tests

import (
	"testing"

	"webtyp.com/json"
	"webtyp.com/model"
	"webtyp.com/router/mock"
	"webtyp.com/auth"
	"webtyp.com/auth/authority"
)

// fakeResolver stands in for rbac.Service, which auth must never import: the
// composition root injects whatever satisfies auth.ActionResolver.
type fakeResolver struct{ grants map[model.Resource]model.Action }

func (f *fakeResolver) AllowedActions(projectID, subjectID string, r model.Resource) model.Action {
	return f.grants[r]
}

const (
	resCatalog = model.Resource("service_catalog")
	resStaff   = model.Resource("staff")
)

// TestMeComposesPermissions proves the composition every app combining
// authority + rbac used to write in its own root now happens in-library.
func TestMeComposesPermissions(t *testing.T) {
	resolver := &fakeResolver{grants: map[model.Resource]model.Action{
		resCatalog: model.Read | model.Update,
		resStaff:   0, // resolves to nothing — must not reach the wire
	}}

	profile := meProfile(t, &auth.Permissions{
		Resolver:  resolver,
		ProjectID: "main",
		Resources: []model.Resource{resCatalog, resStaff},
	})

	if len(profile.Permissions) != 1 {
		t.Fatalf("permissions = %v, want exactly one entry", profile.Permissions)
	}
	if profile.Permissions[0] != "service_catalog:ru" {
		t.Errorf("permissions[0] = %q, want \"service_catalog:ru\"", profile.Permissions[0])
	}
	if !profile.Allows(string(resCatalog)) {
		t.Error("Allows(service_catalog) = false, want true")
	}
	if profile.Allows(string(resStaff)) {
		t.Error("Allows(staff) = true, want false — an empty action set grants nothing")
	}
}

// TestMeClosedByDefault is the other half of the contract: the capability is
// inert at its zero value, so no app gains permissions by upgrading.
func TestMeClosedByDefault(t *testing.T) {
	if p := meProfile(t, nil); len(p.Permissions) != 0 {
		t.Errorf("permissions = %v, want empty with Config.Permissions nil", p.Permissions)
	}

	// A configured resolver slot that was never filled must also stay closed.
	p := meProfile(t, &auth.Permissions{ProjectID: "main", Resources: []model.Resource{resCatalog}})
	if len(p.Permissions) != 0 {
		t.Errorf("permissions = %v, want empty with a nil Resolver", p.Permissions)
	}
}

// TestGrantAllowsRoundTrip pins the wire format to its only producer and its
// only consumer, so neither can drift from the other.
func TestGrantAllowsRoundTrip(t *testing.T) {
	cases := []struct {
		actions model.Action
		encoded string
		allows  bool
	}{
		{model.Read, "service_catalog:r", true},
		{model.Read | model.Update, "service_catalog:ru", true},
		{model.AllActions, "service_catalog:crud", true},
		{0, "", false},
	}

	for _, tc := range cases {
		var p auth.ProfileDTO
		p.Grant(resCatalog, tc.actions)

		if tc.encoded == "" {
			if len(p.Permissions) != 0 {
				t.Errorf("Grant(%v) wrote %v, want nothing", tc.actions, p.Permissions)
			}
		} else if len(p.Permissions) != 1 || p.Permissions[0] != tc.encoded {
			t.Errorf("Grant(%v) = %v, want [%q]", tc.actions, p.Permissions, tc.encoded)
		}

		if got := p.Allows(string(resCatalog)); got != tc.allows {
			t.Errorf("Allows after Grant(%v) = %v, want %v", tc.actions, got, tc.allows)
		}
	}
}

// TestLANOpsGate proves the LAN ops are gated on their own resource: holding
// full "users" administration must NOT let a caller mint a login credential.
func TestLANOpsGate(t *testing.T) {
	db := newTestDB(t)
	m, err := authority.New(db, auth.Config{IDs: testIDs})
	if err != nil {
		t.Fatal(err)
	}
	u, err := m.CreateUser("gate@test.com", "Gate", "")
	if err != nil {
		t.Fatal(err)
	}

	usersAdmin := func(userID string, r model.Resource, a model.Action) bool {
		return r == "users"
	}

	r := &mock.Router{}
	r.Configure(mock.Config{Authorize: usersAdmin})
	m.MountOperations(r)

	for _, op := range []string{auth.OpRegisterLAN, auth.OpUnregisterLAN, auth.OpGetLAN} {
		ctx := &mock.Context{}
		ctx.SetUserID(u.Id)
		r.Invoke("OP", "/"+op, ctx)
		if ctx.Status != 403 {
			t.Errorf("%s with users-only permission: status = %d, want 403", op, ctx.Status)
		}
	}
}

// meProfile runs the real me op and returns what a client would decode.
func meProfile(t *testing.T, perms *auth.Permissions) auth.ProfileDTO {
	t.Helper()
	db := newTestDB(t)
	m, err := authority.New(db, auth.Config{IDs: testIDs, Permissions: perms})
	if err != nil {
		t.Fatal(err)
	}
	u, err := m.CreateUser("me@test.com", "Me", "")
	if err != nil {
		t.Fatal(err)
	}

	reg := &mockOpRegistry{ops: make(map[string]*mockRoute)}
	m.MountOperations(reg)

	ctx := &mock.Context{}
	ctx.SetUserID(u.Id)
	reg.ops[auth.OpMe].handler(ctx)

	var profile auth.ProfileDTO
	if err := json.Decode(ctx.ResponseBody(), &profile); err != nil {
		t.Fatalf("decode profile: %v", err)
	}
	return profile
}
