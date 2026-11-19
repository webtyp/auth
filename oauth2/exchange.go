package oauth2

import (
	"webtyp.com/auth"
	"webtyp.com/fetch"
	"webtyp.com/json"
)

// AuthCodeURL is the provider URL that starts the authorization-code exchange; every provider shares it.
func AuthCodeURL(cfg auth.OAuthConfig, state string) string {
	res := cfg.AuthURL + "?response_type=code"
	res += "&client_id=" + QueryEscape(cfg.ClientID)
	res += "&redirect_uri=" + QueryEscape(cfg.RedirectURL)
	res += "&state=" + QueryEscape(state)
	if len(cfg.Scopes) > 0 {
		res += "&scope="
		for i, s := range cfg.Scopes {
			if i > 0 {
				res += "+"
			}
			res += QueryEscape(s)
		}
	}
	return res
}

// ExchangeCode trades the authorization code for a token at cfg.TokenURL; every provider shares it.
func ExchangeCode(cfg auth.OAuthConfig, code string) (auth.OAuthToken, error) {
	body := "grant_type=authorization_code"
	body += "&code=" + QueryEscape(code)
	body += "&client_id=" + QueryEscape(cfg.ClientID)
	body += "&client_secret=" + QueryEscape(cfg.ClientSecret)
	body += "&redirect_uri=" + QueryEscape(cfg.RedirectURL)

	var res auth.OAuthToken
	var errOut error
	done := make(chan bool)

	fetch.Post(cfg.TokenURL).
		Header("Content-Type", "application/x-www-form-urlencoded").
		Body([]byte(body)).
		Send(func(resp *fetch.Response, err error) {
			defer func() { done <- true }()
			if err != nil {
				errOut = err
				return
			}
			if resp.Status != 200 {
				errOut = auth.ErrInvalidCredentials
				return
			}
			if err := json.Decode(resp.Text(), &res); err != nil {
				errOut = err
				return
			}
		})

	<-done
	return res, errOut
}

// QueryEscape escapes s for a URL query or a form body.
func QueryEscape(s string) string {
	res := ""
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~' {
			res += string(c)
		} else if c == ' ' {
			res += "+"
		} else {
			res += "%" + hexDigit(c>>4) + hexDigit(c&0x0F)
		}
	}
	return res
}

func hexDigit(c byte) string {
	if c < 10 {
		return string('0' + c)
	}
	return string('A' + (c - 10))
}
