package authority

import (
	"webtyp.com/auth"
	"webtyp.com/crud"
	"webtyp.com/fetch"
	"webtyp.com/model"
	"webtyp.com/router"
)

// The browser half of this module: who is signed in and how to sign out. Nobody else names the operation or the
// route (api-harness rule 11).

// opMe is the crud read of who is signed in.
var opMe = router.Operation{Module: Definition.Name, Entity: MeModel.Name, Action: model.Read}

// ReadMe asks the server who is signed in. ok is false when nobody is (no session, or the user no longer exists);
// err is not nil only when the server did not answer (model.ErrorUnreachable). It blocks, so call it from main, not
// from a JS callback.
//
//	me, ok, err := authority.ReadMe(caller)
func ReadMe(caller router.Caller) (me Me, ok bool, err error) {
	var rows MeList
	done := make(chan error, 1)
	caller.Call(opMe, &crud.ReadArgs{}, &rows, func(e error) { done <- e })
	if e := <-done; e != nil {
		if model.KindOf(e) == model.ErrorUnreachable {
			return Me{}, false, e
		}
		return Me{}, false, nil
	}
	if len(rows) == 0 || rows[0] == nil {
		return Me{}, false, nil
	}
	return *rows[0], true, nil
}

// SignOut ends the session of any mode, then calls done (the caller reloads the page).
//
//	authority.SignOut(func() { dom.Navigate("") })
func SignOut(done func()) {
	fetch.Post(auth.PathLogout).Send(func(*fetch.Response, error) { done() })
}

// GrantList is the caller's permissions as model grants; an entry the server wrote illegibly grants nothing.
func (m Me) GrantList() []model.Grant {
	out := make([]model.Grant, 0, len(m.Grants))
	for _, g := range m.Grants {
		actions, err := model.ParseAction(g.Actions)
		if err != nil {
			continue
		}
		out = append(out, model.Grant{Resource: model.Resource(g.Resource), Actions: actions})
	}
	return out
}
