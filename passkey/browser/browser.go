//go:build wasm

package browser

import (
	"webtyp.com/auth/passkey"
	"webtyp.com/base64"
	"webtyp.com/fetch"
	"webtyp.com/fmt"
	"webtyp.com/json"
	"webtyp.com/webauthn"
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
//	button.OnClick(func(Event) { go func() { if err := browser.SignIn(); err == nil { reload() } }() })
func SignIn() error {
	status, data, err := post(passkey.PathVerifyOptions, nil)
	if err != nil {
		return err
	}
	if status != 200 {
		return fmt.Err(errStatus, fmt.Convert(status).String())
	}

	var opts passkey.VerifyOptions
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

	status, _, err = post(passkey.PathVerify, []byte(assertion.RawResponse))
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
func Enroll() error {
	status, data, err := post(passkey.PathRegisterOptions, nil)
	if err != nil {
		return err
	}
	if status != 200 {
		return fmt.Err(errStatus, fmt.Convert(status).String())
	}

	var opts passkey.RegisterOptions
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

	// Note: CreateOptions in webtyp.com/webauthn v0.1.16 does not support ExcludeCredentials
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

	status, _, err = post(passkey.PathRegister, []byte(cred.RawResponse))
	if err != nil {
		return err
	}
	if status != 204 {
		return fmt.Err(errStatus, fmt.Convert(status).String())
	}

	return nil
}
