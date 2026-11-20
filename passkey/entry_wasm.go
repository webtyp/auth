//go:build wasm && browser

package passkey

// The browser half of this mode (WebAuthn exists only in a browser, hence the wasm tag): sign in, enroll, the
// first-administrator setup with the one-time code, and the screen it gives the chassis (view.EntryScreen).

import (
	"webtyp.com/auth"
	"webtyp.com/base64"
	. "webtyp.com/dom"
	. "webtyp.com/html"
	"webtyp.com/fetch"
	"webtyp.com/fmt"
	"webtyp.com/form"
	"webtyp.com/json"
	"webtyp.com/lang"
	"webtyp.com/model"
	"webtyp.com/view"
	"webtyp.com/webauthn"
	"webtyp.com/widget"
)

const errStatus = "passkey: server answered "

// post wraps fetch.Post, waiting for the callback with a channel.
func post(path string, body []byte) (status int, data []byte, err error) {
	ch := make(chan *fetch.Response, 1)
	errCh := make(chan error, 1)

	var req *fetch.Request
	if len(body) > 0 {
		req = fetch.Post(path).Body(body)
	} else {
		req = fetch.Post(path)
	}

	req.Send(func(res *fetch.Response, e error) {
		if e != nil {
			errCh <- e
			return
		}
		ch <- res
	})

	select {
	case res := <-ch:
		return res.Status, res.Body(), nil
	case e := <-errCh:
		return 0, nil, e
	}
}

// SignIn signs in with a passkey of this device: no session is needed. It blocks,
// so call it from a goroutine started by a click (webauthn.Get requires it):
//
//	button.OnClick(func(Event) { go func() { if err := passkey.SignIn(); err == nil { reload() } }() })
func SignIn() error {
	status, data, err := post(PathVerifyOptions, nil)
	if err != nil {
		return err
	}
	if status != 200 {
		return fmt.Err(errStatus, fmt.Convert(status).String())
	}

	var opts VerifyOptions
	if err := json.Decode(data, &opts); err != nil {
		return err
	}

	challenge, err := base64.URLDecode(opts.Challenge)
	if err != nil {
		return err
	}

	allowCredentials := make([][]byte, len(opts.AllowCredentials))
	for i, ac := range opts.AllowCredentials {
		allowCredentials[i], err = base64.URLDecode(ac)
		if err != nil {
			return err
		}
	}

	assertion, err := webauthn.Get(webauthn.GetOptions{
		RPID:             opts.RPID,
		Challenge:        challenge,
		AllowCredentials: allowCredentials,
		UserVerification: "required",
	})
	if err != nil {
		return err
	}

	status, _, err = post(PathVerify, []byte(assertion.RawResponse))
	if err != nil {
		return err
	}
	if status != 204 {
		return fmt.Err(errStatus, fmt.Convert(status).String())
	}

	return nil
}

// Enroll registers a passkey for the person signed in, on this device. The server
// accepts it only on the local door (on the internet door it answers 404). Same
// blocking rule as SignIn.
func Enroll() error { return createPasskey(PathRegisterOptions, nil, PathRegister) }

// Setup creates the first administrator with the one-time code the server wrote in its log, enrolling their passkey
// on this device. Same blocking rule as SignIn.
func Setup(code, name string) error {
	var body []byte
	if err := json.Encode(&auth.SetupData{Code: code, Name: name}, &body); err != nil {
		return err
	}
	return createPasskey(PathSetupOptions, body, PathSetup)
}

// createPasskey asks optionsPath for registration options, creates the credential and sends it to finishPath.
func createPasskey(optionsPath string, optionsBody []byte, finishPath string) error {
	status, data, err := post(optionsPath, optionsBody)
	if err != nil {
		return err
	}
	if status != 200 {
		return fmt.Err(errStatus, fmt.Convert(status).String())
	}

	var opts RegisterOptions
	if err := json.Decode(data, &opts); err != nil {
		return err
	}
	challenge, err := base64.URLDecode(opts.Challenge)
	if err != nil {
		return err
	}
	userID, err := base64.URLDecode(opts.UserID)
	if err != nil {
		return err
	}

	// Note: CreateOptions in webtyp.com/webauthn does not support ExcludeCredentials
	cred, err := webauthn.Create(webauthn.CreateOptions{
		RPID:             opts.RPID,
		UserID:           userID,
		UserName:         opts.UserName,
		Challenge:        challenge,
		ResidentKey:      true,
		UserVerification: "required",
	})
	if err != nil {
		return err
	}

	status, _, err = post(finishPath, []byte(cred.RawResponse))
	if err != nil {
		return err
	}
	if status != 204 {
		return fmt.Err(errStatus, fmt.Convert(status).String())
	}
	return nil
}

const (
	textSignInPasskey   lang.Text = "Sign in with a passkey"
	textPasskeySubtitle lang.Text = "Unlock your phone or computer to continue"
	textPasskeyFailed   lang.Text = "Your passkey could not be verified"
	textCreateAdmin     lang.Text = "Create administrator"
	textSetupSubtitle   lang.Text = "First setup: create the administrator with your passkey"
	textSetupFailed     lang.Text = "Wrong code: check it and try again"
	setupWrapperID                = "passkey-setup-wrapper"
	fieldSetupCode                = "code"
)

// EntryScreen is this mode's entry screen: the setup form while the server waits for its first administrator, the
// passkey button otherwise. A passkey works at every door, so it is always open.
func (k Mode) EntryScreen(d view.BrowserDeps) (view.Entry, bool, error) {
	status, body, err := getSetupState()
	if err != nil {
		return view.Entry{}, false, err
	}
	if status == 200 && string(body) == setupRequired {
		e, err := setupEntry(d)
		return e, err == nil, err
	}
	message := NewString("")
	button := Button().
		Class(widget.NameField.Class(widget.PartSubmit).String()).
		Attr("type", "button").
		Text(lang.Translate(textSignInPasskey).String()).
		OnClick(func(Event) {
			go func() {
				if err := SignIn(); err != nil {
					message.Set(lang.Translate(textPasskeyFailed).String())
					return
				}
				Navigate("")
			}()
		})
	return view.Entry{Subtitle: textPasskeySubtitle, Form: button, Message: message}, true, nil
}

func setupEntry(d view.BrowserDeps) (view.Entry, error) {
	message := NewString("")
	data := &auth.SetupData{}
	f, err := form.New(setupWrapperID, data, d.IDs)
	if err != nil {
		return view.Entry{}, err
	}
	if s, ok := f.Input(fieldSetupCode).(interface{ SetSkipValidation(bool) }); ok {
		s.SetSkipValidation(true)
	}
	f.SubmitLabel(lang.Translate(textCreateAdmin).String())
	f.OnSubmit(func(fd model.Fielder, done func(error)) {
		go func() {
			if err := Setup(data.Code, data.Name); err != nil {
				msg := lang.Translate(textSetupFailed).String()
				message.Set(msg)
				done(fmt.Err(msg))
				return
			}
			Navigate("")
			done(nil)
		}()
	})
	return view.Entry{Subtitle: textSetupSubtitle, Form: f.Render(), Message: message}, nil
}

// getSetupState asks whether the first-administrator setup is pending (404 when it is not offered at all).
func getSetupState() (int, []byte, error) {
	type answer struct {
		status int
		body   []byte
		err    error
	}
	ch := make(chan answer, 1)
	fetch.Get(PathSetup).Send(func(resp *fetch.Response, err error) {
		if err != nil || resp == nil {
			ch <- answer{err: err}
			return
		}
		ch <- answer{status: resp.Status, body: resp.Body()}
	})
	a := <-ch
	return a.status, a.body, a.err
}

var _ view.EntryScreen = Mode{}
