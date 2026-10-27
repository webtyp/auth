//go:build !wasm

package tests

import (
	"errors"
	"testing"

	"webtyp.com/auth"
	"webtyp.com/auth/authority"
	"webtyp.com/json"
	"webtyp.com/model"
	"webtyp.com/router/mock"
)

// fakeGrants stands in for rbac.Service, which auth must never import.
type fakeGrants struct {
	grants []model.Grant
	err    error
}

func (f *fakeGrants) SubjectGrants(projectID, subjectID string) ([]model.Grant, error) {
	return f.grants, f.err
}

const (
	resCatalog = model.Resource("service_catalog")
	resStaff   = model.Resource("staff")
)

func TestMeComposesPermissions(t *testing.T) {
	resolver := &fakeGrants{grants: []model.Grant{
		{Resource: resCatalog, Actions: model.Read | model.Update},
	}}

	profile := meProfile(t, &auth.Permissions{
		Grants:    resolver,
		ProjectID: "main",
	})

	if len(profile.Permissions) != 1 {
		t.Fatalf("permissions = %v, want exactly one entry", profile.Permissions)
	}
	if profile.Permissions[0] != "service_catalog:ru" {
		t.Errorf("permissions[0] = %q, want \"service_catalog:ru\"", profile.Permissions[0])
	}
	if !profile.Can(resCatalog, model.Read) {
		t.Error("Can(service_catalog, Read) = false, want true")
	}
	if profile.Can(resCatalog, model.Delete) {
		t.Error("Can(service_catalog, Delete) = true, want false")
	}
	if profile.Can(resStaff, model.Read) {
		t.Error("Can(staff, Read) = true, want false")
	}
}

func TestMeSendsWildcardAsStored(t *testing.T) {
	resolver := &fakeGrants{grants: []model.Grant{
		{Resource: model.Wildcard, Actions: model.AllActions},
	}}

	profile := meProfile(t, &auth.Permissions{
		Grants:    resolver,
		ProjectID: "main",
	})

	if len(profile.Permissions) != 1 {
		t.Fatalf("permissions = %v, want exactly one entry", profile.Permissions)
	}
	if profile.Permissions[0] != "*:crud" {
		t.Errorf("permissions[0] = %q, want \"*:crud\"", profile.Permissions[0])
	}
	if !profile.Can("anything", model.Delete) {
		t.Error("Can(anything, Delete) = false, want true")
	}
}

func TestMeGrantsErrorIs500(t *testing.T) {
	db := newTestDB(t)
	m, err := authority.New(db, auth.Config{IDs: testIDs, Permissions: &auth.Permissions{
		Grants: &fakeGrants{err: errors.New("db down")}, ProjectID: "main",
	}})
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
	if ctx.Status != 500 {
		t.Fatalf("me with a failing GrantLister: status %d, want 500", ctx.Status)
	}
}

func TestMeClosedByDefault(t *testing.T) {
	if p := meProfile(t, nil); len(p.Permissions) != 0 {
		t.Errorf("permissions = %v, want empty with Config.Permissions nil", p.Permissions)
	}

	p := meProfile(t, &auth.Permissions{ProjectID: "main", Grants: nil})
	if len(p.Permissions) != 0 {
		t.Errorf("permissions = %v, want empty with a nil Grants", p.Permissions)
	}
}

func TestGrantCanRoundTrip(t *testing.T) {
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

		if got := p.Can(resCatalog, tc.actions); got != tc.allows {
			t.Errorf("Can after Grant(%v) = %v, want %v", tc.actions, got, tc.allows)
		}
	}
}

func TestCanIgnoresIllegibleEntry(t *testing.T) {
	p := auth.ProfileDTO{Permissions: []string{"service_catalog:xyz", "nocolon"}}
	if p.Can(resCatalog, model.Read) {
		t.Error("Can(service_catalog, Read) = true on illegible permissions, want false")
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
