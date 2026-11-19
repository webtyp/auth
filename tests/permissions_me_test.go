//go:build !wasm

package tests

import (
	"errors"
	"testing"

	"webtyp.com/auth"
	"webtyp.com/auth/authority"
	"webtyp.com/model"
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

	want := authority.MeGrant{Resource: string(resCatalog), Actions: "ru"}
	if len(profile.Grants) != 1 || profile.Grants[0] != want {
		t.Fatalf("grants = %v, want [%v]", profile.Grants, want)
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

	want := authority.MeGrant{Resource: string(model.Wildcard), Actions: "crud"}
	if len(profile.Grants) != 1 || profile.Grants[0] != want {
		t.Fatalf("grants = %v, want [%v]", profile.Grants, want)
	}
}

func TestMeGrantsErrorIs500(t *testing.T) {
	db := newTestDB(t)
	m, err := authority.New(db, auth.Config{IDs: testIDs, Events: &mockPublisher{}, Permissions: &auth.Permissions{
		Grants: &fakeGrants{err: errors.New("db down")}, ProjectID: "main",
	}})
	if err != nil {
		t.Fatal(err)
	}
	u, err := m.CreateUser("me@test.com", "Me", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := readMe(m, u.Id); model.KindOf(err) != model.ErrorInternal {
		t.Fatalf("me with a failing GrantLister: err %v, want an internal error", err)
	}
}

func TestMeClosedByDefault(t *testing.T) {
	if p := meProfile(t, nil); len(p.Grants) != 0 {
		t.Errorf("grants = %v, want empty with Config.Permissions nil", p.Grants)
	}

	p := meProfile(t, &auth.Permissions{ProjectID: "main", Grants: nil})
	if len(p.Grants) != 0 {
		t.Errorf("grants = %v, want empty with a nil Grants", p.Grants)
	}
}

// meProfile runs the real crud read me as the signed-in user and returns what a client receives.
func meProfile(t *testing.T, perms *auth.Permissions) *authority.Me {
	t.Helper()
	db := newTestDB(t)
	m, err := authority.New(db, auth.Config{IDs: testIDs, Events: &mockPublisher{}, Permissions: perms})
	if err != nil {
		t.Fatal(err)
	}
	u, err := m.CreateUser("me@test.com", "Me", "")
	if err != nil {
		t.Fatal(err)
	}
	me, err := readMe(m, u.Id)
	if err != nil {
		t.Fatalf("read me: %v", err)
	}
	return me
}
