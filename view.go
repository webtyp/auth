package auth

import (
	"webtyp.com/model"
	"webtyp.com/router"
	"webtyp.com/view"
)

// NewView builds the user-administration Presenter — the tech-agnostic engine a
// renderer (crudview, or any other) wraps. The app decides which renderer draws it.
func NewView(caller router.Caller) view.Presenter {
	b := view.NewCallerLister(view.NewRecords().Caller(caller),
		view.Ops{Module: ModelName, List: OpListUsers, Save: OpUpsertUser, Delete: OpDeleteUser},
		func() model.ModelSlice { return &UserList{} })
	return view.New(b, &User{}, view.WithTitle("Usuarios"))
}

