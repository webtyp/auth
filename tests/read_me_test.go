//go:build !wasm

package tests

import (
	"testing"

	"webtyp.com/auth"
	"webtyp.com/auth/authority"
	"webtyp.com/crud"
	"webtyp.com/model"
	"webtyp.com/router"
)

// downCaller is a server that does not answer.
type downCaller struct{}

type unreachable struct{}

func (unreachable) Error() string         { return "no answer" }
func (unreachable) Kind() model.ErrorKind { return model.ErrorUnreachable }

func (downCaller) Call(op router.Operation, args model.Encodable, into model.Decodable, done func(error)) {
	done(unreachable{})
}
func (downCaller) Dispatch(op router.Operation, args model.Encodable) {}

func TestReadMe_SignedInUserWithGrants(t *testing.T) {
	db := newTestDB(t)
	m, err := authority.New(db, auth.Config{IDs: testIDs, Events: &mockPublisher{}, Permissions: &auth.Permissions{
		ProjectID: "main", Grants: &fakeGrants{grants: []model.Grant{{Resource: "patient", Actions: model.Read}}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	u, _ := m.CreateUser("ana@test.com", "Ana", "")
	me, ok, err := authority.ReadMe(crud.LoopbackActingAs(nil, u.Id, m))
	if err != nil || !ok || me.Id != u.Id {
		t.Fatalf("ReadMe = %+v ok %v err %v, want Ana", me, ok, err)
	}
	if g := me.GrantList(); len(g) != 1 || !g[0].Matches("patient", model.Read) {
		t.Fatalf("grants = %+v, want patient:r", g)
	}
}

func TestReadMe_DeletedUserIsNobody(t *testing.T) {
	db := newTestDB(t)
	m, _ := authority.New(db, auth.Config{IDs: testIDs, Events: &mockPublisher{}})
	if _, ok, err := authority.ReadMe(crud.LoopbackActingAs(nil, "gone", m)); ok || err != nil {
		t.Fatalf("ok %v err %v, want nobody and no error", ok, err)
	}
}

func TestReadMe_ServerDownIsAnError(t *testing.T) {
	if _, ok, err := authority.ReadMe(downCaller{}); ok || err == nil {
		t.Fatalf("ok %v err %v, want an error so the screen says the server did not answer", ok, err)
	}
}
