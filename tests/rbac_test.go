//go:build !wasm

package tests

import (
	"testing"

	"webtyp.com/auth"
	"webtyp.com/auth/authority"
	"webtyp.com/crud"
	"webtyp.com/json"
	"webtyp.com/model"
	"webtyp.com/router"
	"webtyp.com/router/mock"
)

func TestTools_Me(t *testing.T) {
	db := newTestDB(t)
	m, _ := authority.New(db, auth.Config{IDs: testIDs})

	userCRUD := getHandler(m, "users")
	res, err := userCRUD.Create(auth.User{Email: "me@test.com", Name: "Me User"})
	if err != nil {
		t.Fatal(err)
	}
	u := res.(auth.User)

	t.Run("Authenticated me returns profile", func(t *testing.T) {
		ctx := &mock.Context{}
		ctx.SetUserID(u.Id)

		callMe(m, ctx)

		if ctx.Status != 0 && ctx.Status != 200 {
			t.Fatalf("handler returned status: %d", ctx.Status)
		}

		var profile auth.ProfileDTO
		if err := json.Decode(ctx.ResponseBody(), &profile); err != nil {
			t.Fatalf("Decode failed: %v", err)
		}
		if profile.Id != u.Id || profile.Email != u.Email {
			t.Errorf("mismatch: got %v, want %v", profile, u)
		}
	})

	t.Run("Anonymous me returns error", func(t *testing.T) {
		ctx := &mock.Context{}
		// No userID set
		callMe(m, ctx)
		if ctx.Status != 401 && ctx.Status != 403 {
			t.Errorf("an anonymous caller must be refused (401 or 403), got %d", ctx.Status)
		}
	})
}

// TestUser_CrudThroughLoopback walks the four actions of the user entity through crud, as the admin screen does.
func TestUser_CrudThroughLoopback(t *testing.T) {
	db := newTestDB(t)
	m, _ := authority.New(db, auth.Config{IDs: testIDs})
	caller := crud.LoopbackActingAs(nil, "admin-1", m)
	op := func(action model.Action) router.Operation {
		return router.Operation{Module: authority.ModelName, Entity: "user", Action: action}
	}

	var created authority.User
	var err error
	caller.Call(op(model.Create), &crud.CreateArgs{Records: []model.Model{&authority.User{Email: "a@x.cl", Name: "Ana"}}}, &created, func(e error) { err = e })
	if err != nil {
		t.Fatalf("user.create: %v", err)
	}
	got, gerr := m.GetUser(created.Id)
	if gerr != nil || got.Status != "active" || got.CreatedAt == 0 {
		t.Fatalf("created user must be active and stamped, got %+v, %v", got, gerr)
	}

	caller.Call(op(model.Update), &crud.UpdateArgs{IDs: []string{created.Id}, Fields: []string{"name"}, Record: &authority.User{Name: "Ana María"}}, nil, func(e error) { err = e })
	if err != nil {
		t.Fatalf("user.update: %v", err)
	}
	if got, _ := m.GetUser(created.Id); got.Name != "Ana María" {
		t.Fatalf("the update was not seen by GetUser (cache not invalidated): %+v", got)
	}

	caller.Call(op(model.Update), &crud.UpdateArgs{IDs: []string{created.Id}, Fields: []string{"status"}, Record: &authority.User{Status: "suspended"}}, nil, func(e error) { err = e })
	if err == nil {
		t.Fatal("status must not be editable through user.update")
	}

	caller.Call(op(model.Delete), &crud.DeleteArgs{IDs: []string{created.Id}}, nil, func(e error) { err = e })
	if err != nil {
		t.Fatalf("user.delete: %v", err)
	}
	if _, gerr := m.GetUser(created.Id); gerr == nil {
		t.Fatal("the deleted user is still readable")
	}
}

func TestNew_Validation(t *testing.T) {
	db := newTestDB(t)

	t.Run("Cookie strategy (default) needs no secret", func(t *testing.T) {
		_, err := authority.New(db, auth.Config{IDs: testIDs})
		if err != nil {
			t.Fatal(err)
		}
	})
}
