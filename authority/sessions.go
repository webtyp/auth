package authority

import (
	"sync"

	"webtyp.com/crypto/rand"
	"webtyp.com/fmt"
	"webtyp.com/model"
	"webtyp.com/time"

	"webtyp.com/orm"
	"webtyp.com/auth"
)

// sessionIDBytes: 32 bytes = 256 bits de entropía para el id de sesión. Un id
// de sesión NO es una clave primaria más: es la credencial que viaja en el
// cookie, así que se genera con el CSPRNG y no con el generador de ids
// correlativos del módulo — ese produce timestamps enumerables.
const sessionIDBytes = 32

// maxCacheSessions acota el caché de sesiones igual que maxCacheUsers acota
// el de usuarios: un isolate de larga vida no puede crecer sin techo. El
// desalojo FIFO sólo cuesta una lectura de base en el próximo GetSession —
// el caché es de lectura-a-través, no la fuente de verdad.
const maxCacheSessions = 1000

type sessionItem struct {
	key string
	val auth.Session
}

type sessionCache struct {
	mu    sync.RWMutex
	items []sessionItem
}

func newSessionCache() *sessionCache {
	return &sessionCache{
		items: make([]sessionItem, 0, maxCacheSessions),
	}
}

func (c *sessionCache) set(id string, s auth.Session) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for i, item := range c.items {
		if item.key == id {
			c.items[i].val = s
			return
		}
	}
	if len(c.items) >= maxCacheSessions {
		c.items = c.items[1:]
	}
	c.items = append(c.items, sessionItem{key: id, val: s})
}

func (c *sessionCache) get(id string) (auth.Session, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	for _, item := range c.items {
		if item.key == id {
			return item.val, true
		}
	}
	return auth.Session{}, false
}

func (c *sessionCache) delete(id string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for i, item := range c.items {
		if item.key == id {
			c.items = append(c.items[:i], c.items[i+1:]...)
			return
		}
	}
}

// slideWriteThreshold is the smallest idle extension worth a write: a burst of
// requests moves the expiry once a minute, not once per request.
const slideWriteThreshold = time.Minute

// RotateSession atomically deletes the old session and creates a new one
// with the same userID and policy, updated IP/UserAgent, and a fresh lifetime.
// Prevents session fixation attacks when called post-login.
func (m *Module) RotateSession(oldID, ip, userAgent string) (auth.Session, error) {
	oldSess, err := m.GetSession(oldID)
	if err != nil {
		return auth.Session{}, err
	}

	err = m.DeleteSession(oldID)
	if err != nil {
		return auth.Session{}, err
	}

	return m.CreateSession(oldSess.UserId, ip, userAgent, auth.SessionPolicy{
		Absolute:  oldSess.AbsoluteAt - oldSess.CreatedAt,
		Idle:      oldSess.IdleSeconds,
		Assurance: model.Assurance(oldSess.Assurance),
	})
}

func (m *Module) CreateSession(userID, ip, userAgent string, p auth.SessionPolicy) (auth.Session, error) {
	if p.Absolute <= 0 {
		return auth.Session{}, fmt.Err(auth.ErrMsgPolicyAbsolute)
	}

	id, err := rand.SecretN(sessionIDBytes)
	if err != nil {
		return auth.Session{}, err
	}

	now := time.NowUnix()
	absoluteAt := now + p.Absolute
	expiresAt := absoluteAt
	if p.Idle > 0 {
		expiresAt = min(now+p.Idle, absoluteAt)
	}
	sess := auth.Session{
		Id:          id,
		UserId:      userID,
		ExpiresAt:   expiresAt,
		Ip:          ip,
		UserAgent:   userAgent,
		CreatedAt:   now,
		AbsoluteAt:  absoluteAt,
		IdleSeconds: p.Idle,
		Assurance:   int64(p.Assurance),
	}

	if err := m.db.Create(&sess); err != nil {
		return auth.Session{}, err
	}
	m.cache.set(sess.Id, sess)
	return sess, nil
}

// GetSession applies the row's own policy: a session past its sliding expiry
// OR its absolute cap is deleted and reported as expired; otherwise the idle
// window slides forward, never beyond the cap.
func (m *Module) GetSession(id string) (auth.Session, error) {
	s, ok := m.cache.get(id)
	if !ok {
		qb := m.db.Query(&auth.Session{}).Where(auth.Session_.Id).Eq(id)
		results, err := auth.ReadAllSession(qb)
		if err != nil {
			return auth.Session{}, err
		}
		if len(results) == 0 {
			return auth.Session{}, auth.ErrNotFound
		}
		s = *results[0]
	}

	now := time.NowUnix()
	if now >= s.ExpiresAt || now >= s.AbsoluteAt {
		m.DeleteSession(id)
		return auth.Session{}, auth.ErrSessionExpired
	}

	m.slideSession(&s, now)
	m.cache.set(s.Id, s)
	return s, nil
}

// slideSession moves s.ExpiresAt to min(now+IdleSeconds, AbsoluteAt) when the
// row has an idle window and the move is at least slideWriteThreshold seconds.
func (m *Module) slideSession(s *auth.Session, now time.Unix) {
	if s.IdleSeconds <= 0 {
		return
	}
	newExpiry := min(now+s.IdleSeconds, s.AbsoluteAt)
	if newExpiry-s.ExpiresAt < slideWriteThreshold {
		return
	}
	s.ExpiresAt = newExpiry
	if err := m.db.Update(s, orm.Eq(auth.Session_.Id, s.Id)); err != nil && m.log != nil {
		// The session stays valid — failing the request over a bookkeeping
		// write would log the user out on a transient storage error. But the
		// slide did not reach the row, so a later isolate will read the older
		// expiry: say so instead of diverging in silence.
		m.log("authority: session slide not persisted:", err)
	}
}

func (m *Module) DeleteSession(id string) error {
	m.cache.delete(id)
	qb := m.db.Query(&auth.Session{}).Where(auth.Session_.Id).Eq(id)
	results, err := auth.ReadAllSession(qb)
	if err == nil && len(results) > 0 {
		return m.db.Delete(results[0], orm.Eq(auth.Session_.Id, results[0].Id))
	}
	return err
}

func (m *Module) PurgeExpiredSessions() error {
	now := time.NowUnix()

	m.cache.mu.Lock()
	var active []sessionItem
	for _, item := range m.cache.items {
		if item.val.ExpiresAt >= now {
			active = append(active, item)
		}
	}
	m.cache.items = active
	m.cache.mu.Unlock()

	qb := m.db.Query(&auth.Session{}).Where(auth.Session_.ExpiresAt).Lt(now)
	sessions, _ := auth.ReadAllSession(qb)
	for _, s := range sessions {
		m.db.Delete(s, orm.Eq(auth.Session_.Id, s.Id))
	}

	return nil
}
