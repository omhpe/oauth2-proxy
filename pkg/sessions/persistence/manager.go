package persistence

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
)

// Manager wraps a Store and handles the implementation details of the
// sessions.SessionStore with its use of session tickets
type Manager struct {
	Store   Store
	Options *options.Cookie
}

// NewManager creates a Manager that can wrap a Store and manage the
// sessions.SessionStore implementation details
func NewManager(store Store, cookieOpts *options.Cookie) *Manager {
	return &Manager{
		Store:   store,
		Options: cookieOpts,
	}
}

// Save saves a session in a persistent Store. Save will generate (or reuse an
// existing) ticket which manages unique per session encryption & retrieval
// from the persistent data store.
func (m *Manager) Save(rw http.ResponseWriter, req *http.Request, s *sessions.SessionState) error {
	if s.CreatedAt == nil || s.CreatedAt.IsZero() {
		s.CreatedAtNow()
	}

	tckt, err := decodeTicketFromRequest(req, m.Options)
	if err != nil {
		tckt, err = newTicket(m.Options)
		if err != nil {
			return fmt.Errorf("error creating a session ticket: %v", err)
		}
	}
	// // Start
	// if _, ok := interface{}(m.Store).(*redis.SessionStore); ok {
	keyName := fmt.Sprintf("sessionlist-%s", s.User)
	keyVal, keyerr := m.Store.Load(req.Context(), keyName)
	var ticket []byte
	if keyerr != nil {
		ticket = []byte(tckt.id)
	} else if !(strings.Contains(string(keyVal), tckt.id)) {
		ticket = []byte(fmt.Sprintf("%s:%s", keyVal, tckt.id))
	} else {
		ticket = keyVal
	}

	err = saveSessionKey(req.Context(), keyName, ticket, tckt.options.Expire, m, s)
	if err != nil {
		return err
	}
	// }
	// // End

	err = tckt.saveSession(s, func(key string, val []byte, exp time.Duration) error {
		return m.Store.Save(req.Context(), key, val, exp)
	})
	if err != nil {
		return err
	}

	return tckt.setCookie(rw, req, s)
}

func saveSessionKey(ctx context.Context, keyName string, ticket []byte, exp time.Duration, m *Manager, s *sessions.SessionState) error {
	err := s.ObtainLock(ctx, exp)
	if err != nil {
		return fmt.Errorf("error occurred while trying to obtain lock: %v", err)
	}
	defer func() {
		if s == nil {
			return
		}
		if err := s.ReleaseLock(ctx); err != nil {
			logger.Errorf("unable to release lock: %v", err)
		}
	}()
	err = m.Store.Save(ctx, keyName, ticket, exp)
	return err
}

// Load reads sessions.SessionState information from a session store. It will
// use the session ticket from the http.Request's cookie.
func (m *Manager) Load(req *http.Request) (*sessions.SessionState, error) {
	tckt, err := decodeTicketFromRequest(req, m.Options)
	if err != nil {
		return nil, err
	}

	return tckt.loadSession(
		func(key string) ([]byte, error) {
			return m.Store.Load(req.Context(), key)
		},
		m.Store.Lock,
	)
}

// Clear clears any saved session information for a given ticket cookie.
// Then it clears all session data for that ticket in the Store.
func (m *Manager) Clear(rw http.ResponseWriter, req *http.Request) error {
	tckt, err := decodeTicketFromRequest(req, m.Options)
	if err != nil {
		// Always clear the cookie, even when we can't load a cookie from
		// the request
		tckt = &ticket{
			options: m.Options,
		}
		tckt.clearCookie(rw, req)
		// Don't raise an error if we didn't have a Cookie
		if err == http.ErrNoCookie {
			return nil
		}
		return fmt.Errorf("error decoding ticket to clear session: %v", err)
	}

	tckt.clearCookie(rw, req)
	return tckt.clearSession(func(key string) error {
		return m.Store.Clear(req.Context(), key)
	})
}

// Clear clears any saved session information for a given ticket cookie.
// Then it clears all session data for that ticket in the Store.
func (m *Manager) ClearAll(rw http.ResponseWriter, req *http.Request, s *sessions.SessionState, password string, user string) error {
	tckt, err := decodeTicketFromRequest(req, m.Options)
	if err != nil {
		// Always clear the cookie, even when we can't load a cookie from
		// the request
		tckt = &ticket{
			options: m.Options,
		}
		tckt.clearCookie(rw, req)
		// Don't raise an error if we didn't have a Cookie
		if err == http.ErrNoCookie {
			return nil
		}
		return fmt.Errorf("error decoding ticket to clear session: %v", err)
	}

	tckt.clearCookie(rw, req)
	err = tckt.clearSession(func(key string) error {
		return m.Store.ClearAll(req.Context(), s, tckt.options.Expire, key, password, user)
	})
	return err
}

// VerifyConnection validates the underlying store is ready and connected
func (m *Manager) VerifyConnection(ctx context.Context) error {
	return m.Store.VerifyConnection(ctx)
}
