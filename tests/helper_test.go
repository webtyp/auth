package tests

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"

	"webtyp.com/auth"
	"webtyp.com/auth/authority"
	"webtyp.com/crud"
	"webtyp.com/events"
	"webtyp.com/model"
	"webtyp.com/router"
	"webtyp.com/securityevent"
)

type testIDGenerator struct {
	mu  sync.Mutex
	seq int64
}

func (g *testIDGenerator) NewID() string {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.seq++
	b := make([]byte, 8)
	rand.Read(b)
	return fmt.Sprintf("id_%d_%s", g.seq, hex.EncodeToString(b))
}

var testIDs = &testIDGenerator{}

type mockPublisher struct {
	mu     sync.Mutex
	events []events.Event
}

func (p *mockPublisher) Publish(e events.Event) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.events = append(p.events, e)
}

func (p *mockPublisher) SecurityEvents() []securityevent.Event {
	p.mu.Lock()
	defer p.mu.Unlock()
	var list []securityevent.Event
	for _, e := range p.events {
		if e.Topic == securityevent.Topic {
			if se, ok := e.Payload.(*securityevent.Event); ok {
				list = append(list, *se)
			}
		}
	}
	return list
}

// publisherFunc is a broker that hands every event to a function.
type publisherFunc func(events.Event)

func (f publisherFunc) Publish(e events.Event) { f(e) }

// reporterFunc is a reporter that hands every security event to fn: what a test that collects them passes to a mode.
func reporterFunc(fn func(securityevent.Event)) securityevent.Reporter {
	r, _ := securityevent.New(publisherFunc(func(e events.Event) {
		if se, ok := e.Payload.(*securityevent.Event); ok {
			fn(*se)
		}
	}))
	return r
}

// hasSecurityEvent reports whether events holds one of kind with reason ("" = any reason).
func hasSecurityEvent(events []securityevent.Event, kind securityevent.Kind, reason securityevent.Reason) bool {
	for _, e := range events {
		if e.Kind == kind && (reason == "" || e.Reason == reason) {
			return true
		}
	}
	return false
}

type mockRoute struct {
	authenticated bool
	requiredRes   model.Resource
	requiredAct   model.Action
	acceptedArg   any
	handler       router.HandlerFunc
}

func (r *mockRoute) Authenticated() router.Route {
	r.authenticated = true
	return r
}

func (r *mockRoute) Requires(res model.Resource, action model.Action) router.Route {
	r.requiredRes = res
	r.requiredAct = action
	return r
}

func (r *mockRoute) Accepts(arg model.Fielder) router.Route {
	r.acceptedArg = arg
	return r
}

func (r *mockRoute) Public() router.Route {
	return r
}

func (r *mockRoute) Describe(string) router.Route {
	return r
}

type mockOpRegistry struct {
	ops map[string]*mockRoute
}

func (reg *mockOpRegistry) Operation(name string, h router.HandlerFunc) router.Route {
	r := &mockRoute{handler: h}
	reg.ops[name] = r
	return r
}

func (r *mockRoute) RequiresMFA() router.Route {
	return r
}

var testPolicy = auth.SessionPolicy{Absolute: 3600, Assurance: model.AssuranceSingleFactor}

// readMe reads the entity me through crud, signed in as userID ("" = no session), as the browser does.
func readMe(m *authority.Module, userID string) (*authority.Me, error) {
	var rows authority.MeList
	var err error
	op := router.Operation{Module: authority.ModelName, Entity: "me", Action: model.Read}
	crud.LoopbackActingAs(nil, userID, m).Call(op, &crud.ReadArgs{}, &rows, func(e error) { err = e })
	if err != nil {
		return nil, err
	}
	if len(rows) != 1 {
		return nil, errors.New("me must answer exactly one row")
	}
	return rows[0], nil
}
