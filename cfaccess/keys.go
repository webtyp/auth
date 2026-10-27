package cfaccess

import (
	"sync"

	"webtyp.com/fetch"
	"webtyp.com/fmt"
	"webtyp.com/jwt"
	"webtyp.com/time"
)

const (
	httpsScheme = "https://"
	certsPath   = "/cdn-cgi/access/certs"
	httpOK      = 200

	// KeysMaxAge is how long (seconds) a fetched key set is reused before
	// Keys fetches it again.
	KeysMaxAge = 3600
	// RefreshMinInterval is the minimum time (seconds) between two network
	// fetches, whether forced by Refresh or retried after a failure.
	RefreshMinInterval = 60

	// ErrMsgKeysStatus: the certs endpoint answered with a non-200 status.
	ErrMsgKeysStatus = "cfaccess: certs endpoint status"
)

// CertsURL is where Cloudflare Access publishes the signing keys of a team.
//
// Example: cfaccess.CertsURL("acme.cloudflareaccess.com") → "https://acme.cloudflareaccess.com/cdn-cgi/access/certs"
func CertsURL(teamDomain string) string { return httpsScheme + teamDomain + certsPath }

// KeySource supplies the keys Access signs with. Keys returns the cached set
// (fetching it when absent or older than KeysMaxAge). Refresh fetches again
// unless the last fetch was less than RefreshMinInterval seconds ago; the
// Authenticator calls it once when a token's key is unknown (Access rotated
// its keys).
type KeySource interface {
	Keys() (jwt.KeySet, error)
	Refresh() (jwt.KeySet, error)
}

// NewKeySource fetches the JWKS at certsURL over HTTP(S) with webtyp/fetch.
//
// Example: keys := cfaccess.NewKeySource(cfaccess.CertsURL(team))
func NewKeySource(certsURL string) KeySource { return &remoteKeys{url: certsURL} }

type remoteKeys struct {
	url string

	mu        sync.Mutex
	set       jwt.KeySet
	err       error // last fetch error; nil after a success
	fetchedAt int64 // unix seconds of the last successful fetch; 0 = never
	triedAt   int64 // unix seconds of the last network attempt; 0 = never
}

func (r *remoteKeys) Keys() (jwt.KeySet, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.fetchedAt != 0 && now()-r.fetchedAt < KeysMaxAge {
		return r.set, nil
	}
	return r.fetchLocked()
}

func (r *remoteKeys) Refresh() (jwt.KeySet, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.fetchLocked()
}

// fetchLocked is the only place the network is used. Within
// RefreshMinInterval of the previous attempt it answers from memory: the
// cached set after a success, the same error after a failure (a failing
// endpoint is never hammered once per request).
func (r *remoteKeys) fetchLocked() (jwt.KeySet, error) {
	if r.triedAt != 0 && now()-r.triedAt < RefreshMinInterval {
		if r.err != nil {
			return jwt.KeySet{}, r.err
		}
		return r.set, nil
	}
	r.triedAt = now()
	body, err := getText(r.url)
	if err == nil {
		var set jwt.KeySet
		set, err = jwt.ParseKeySet(body)
		if err == nil {
			r.set, r.err, r.fetchedAt = set, nil, r.triedAt
			return set, nil
		}
	}
	r.err = err
	return jwt.KeySet{}, err
}

// getText waits for webtyp/fetch's callback (same pattern as
// oauth2/provider/google).
func getText(url string) (string, error) {
	var body string
	var errOut error
	done := make(chan bool)
	fetch.Get(url).Send(func(resp *fetch.Response, err error) {
		defer func() { done <- true }()
		if err != nil {
			errOut = err
			return
		}
		if resp.Status != httpOK {
			errOut = fmt.Err(ErrMsgKeysStatus, resp.Status)
			return
		}
		body = resp.Text()
	})
	<-done
	return body, errOut
}

func now() int64 { return int64(time.NowUnix()) }
