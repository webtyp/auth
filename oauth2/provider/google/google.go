package google

import (
	"webtyp.com/auth"
	"webtyp.com/auth/oauth2"
	"webtyp.com/fetch"
	"webtyp.com/json"
	"webtyp.com/model"
)

const (
	googleAuthURL  = "https://accounts.google.com/o/oauth2/auth"
	googleTokenURL = "https://oauth2.googleapis.com/token"
)

// ProviderName identifica a este proveedor en las rutas y en el almacen de
// estado. Un consumidor lo usa con auth.PathOAuthStart / PathOAuthCallback.
const ProviderName = "google"

type GoogleProvider struct {
	ClientID     string
	ClientSecret string
	RedirectURL  string
}

func (p *GoogleProvider) Name() string {
	return ProviderName
}

func (p *GoogleProvider) config() auth.OAuthConfig {
	return auth.OAuthConfig{
		ClientID:     p.ClientID,
		ClientSecret: p.ClientSecret,
		RedirectURL:  p.RedirectURL,
		Scopes:       []string{"https://www.googleapis.com/auth/userinfo.email", "https://www.googleapis.com/auth/userinfo.profile"},
		AuthURL:      googleAuthURL,
		TokenURL:     googleTokenURL,
	}
}

func (p *GoogleProvider) AuthCodeURL(state string) string {
	return oauth2.AuthCodeURL(p.config(), state)
}

func (p *GoogleProvider) ExchangeCode(code string) (auth.OAuthToken, error) {
	return oauth2.ExchangeCode(p.config(), code)
}

type googleData struct {
	ID            string
	Email         string
	VerifiedEmail bool
	Name          string
	Picture       string
}

func (d *googleData) EncodeFields(w model.FieldWriter) {}
func (d *googleData) IsNil() bool                      { return false }
func (d *googleData) DecodeFields(r model.FieldReader) {
	d.ID, _ = r.String("id")
	d.Email, _ = r.String("email")
	d.VerifiedEmail, _ = r.Bool("verified_email")
	d.Name, _ = r.String("name")
	d.Picture, _ = r.String("picture")
}

func (p *GoogleProvider) GetUserInfo(token auth.OAuthToken) (auth.OAuthUserInfo, error) {
	var res auth.OAuthUserInfo
	var errOut error
	done := make(chan bool)

	fetch.Get("https://www.googleapis.com/oauth2/v2/userinfo").
		Header("Authorization", "Bearer "+token.AccessToken).
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
			var data googleData
			if err := json.Decode(resp.Text(), &data); err != nil {
				errOut = err
				return
			}
			res = auth.OAuthUserInfo{
				ID:            data.ID,
				Email:         data.Email,
				EmailVerified: data.VerifiedEmail,
				Name:          data.Name,
				Avatar:        data.Picture,
			}
		})

	<-done
	return res, errOut
}
