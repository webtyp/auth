package trustedip

import (
	"webtyp.com/auth"
	. "webtyp.com/dom"
	"webtyp.com/fetch"
	"webtyp.com/fmt"
	"webtyp.com/form"
	"webtyp.com/json"
	"webtyp.com/lang"
	"webtyp.com/model"
	"webtyp.com/view"
)

// The browser half of this mode: the screen it gives the chassis (view.EntryScreen). It asks its own route which
// screen applies at this door (ARCHITECTURE D78): 404 = not open here (the Internet), "required" = first setup,
// otherwise the key form.
const (
	textKey           lang.Text = "Key"
	textSignIn        lang.Text = "Sign in"
	textName          lang.Text = "Name"
	textCreateAdmin   lang.Text = "Create administrator"
	textSetupFailed   lang.Text = "The administrator could not be created. Check the RUT entered."
	textLoginDenied   lang.Text = "Access not authorized on this device"
	textLoginSubtitle lang.Text = "Enter your key to continue"
	textSetupSubtitle lang.Text = "First setup: create the administrator"
	labelRUT                    = "RUT"
	loginWrapperID              = "login-wrapper"
	setupWrapperID              = "setup-wrapper"
	fieldCode                   = "code"
	fieldName                   = "name"
)

// EntryScreen is this mode's entry screen at this door: the first-setup form while no administrator exists, the key
// form otherwise, and open=false from the Internet.
func (t Mode) EntryScreen(d view.BrowserDeps) (view.Entry, bool, error) {
	status, body, err := getStatus(auth.PathSetup)
	switch {
	case err != nil:
		return view.Entry{}, false, err
	case status == statusNotFound:
		return view.Entry{}, false, nil
	case status != 200:
		return view.Entry{}, false, ErrAdminsUnreadable
	case string(body) == setupRequired:
		e, err := setupEntry(d)
		return e, err == nil, err
	}
	e, err := loginEntry(d)
	return e, err == nil, err
}

func loginEntry(d view.BrowserDeps) (view.Entry, error) {
	message := NewString("")
	data := &auth.RUTLoginData{}
	f, err := form.New(loginWrapperID, data, d.IDs)
	if err != nil {
		return view.Entry{}, err
	}
	if inp := f.Input(fieldCode); inp != nil {
		title(inp, lang.Translate(textKey).String(), true)
		if m, ok := inp.(interface{ SetMasked(bool) }); ok {
			m.SetMasked(true)
		}
	}
	f.SubmitLabel(lang.Translate(textSignIn).String())
	f.OnSubmit(func(fd model.Fielder, done func(error)) {
		post(auth.PathLoginRUT, data, done, func() {
			msg := lang.Translate(textLoginDenied).String()
			message.Set(msg)
			done(fmt.Err(msg))
		})
	})
	return view.Entry{Subtitle: textLoginSubtitle, Form: f.Render(), Message: message}, nil
}

func setupEntry(d view.BrowserDeps) (view.Entry, error) {
	message := NewString("")
	data := &auth.SetupData{}
	f, err := form.New(setupWrapperID, data, d.IDs)
	if err != nil {
		return view.Entry{}, err
	}
	title(f.Input(fieldCode), labelRUT, true)
	title(f.Input(fieldName), lang.Translate(textName).String(), false)
	f.SubmitLabel(lang.Translate(textCreateAdmin).String())
	f.OnSubmit(func(fd model.Fielder, done func(error)) {
		post(auth.PathSetup, data, done, func() {
			msg := lang.Translate(textSetupFailed).String()
			message.Set(msg)
			done(fmt.Err(msg))
		})
	})
	return view.Entry{Subtitle: textSetupSubtitle, Form: f.Render(), Message: message}, nil
}

// title labels an input and, when skipValidation, lets any text through (the server checks the RUT).
func title(inp any, label string, skipValidation bool) {
	if t, ok := inp.(interface{ SetTitle(string) }); ok {
		t.SetTitle(label)
	}
	if s, ok := inp.(interface{ SetSkipValidation(bool) }); ok && skipValidation {
		s.SetSkipValidation(true)
	}
}

// getStatus asks path and waits for the answer; valid because the session is built from main, not a JS callback.
func getStatus(path string) (int, []byte, error) {
	type answer struct {
		status int
		body   []byte
		err    error
	}
	ch := make(chan answer, 1)
	fetch.Get(path).Send(func(resp *fetch.Response, err error) {
		if err != nil || resp == nil {
			ch <- answer{err: err}
			return
		}
		ch <- answer{status: resp.Status, body: resp.Body()}
	})
	a := <-ch
	return a.status, a.body, a.err
}

// post sends data to path; on success the page reloads into the session the server just issued.
func post(path string, data model.Encodable, done func(error), refused func()) {
	var out []byte
	if err := json.Encode(data, &out); err != nil {
		done(err)
		return
	}
	fetch.Post(path).ContentTypeJSON().Body(out).Send(func(resp *fetch.Response, err error) {
		if err != nil {
			done(err)
			return
		}
		if resp.Status != 200 {
			refused()
			return
		}
		Navigate("")
		done(nil)
	})
}

var _ view.EntryScreen = Mode{}
