---
PLAN: "feat: SecurityEventType.String() — security events log a name, not a number"
EXECUTOR: jules
REVIEWER: none
---

> This plan is dispatched via the CodeJob workflow. See skill: agents-workflow.

# Plan — `SecurityEventType` gets a readable name

## Why

`auth.SecurityEvent.Type` is a `SecurityEventType` (`uint8` enum, `user.go`).
Applications log security events by passing the event to their logger, e.g.
`veltylabs/mjosefa-cms`:

```go
logger("app: SECURITY EVENT — type:", e.Type, "userID:", e.UserID, …)
```

which prints:

```
app: SECURITY EVENT — type: 6 userID: 1789255672822246364
```

"type: 6" means nothing to the person reading the log; they must count the
`iota` list in `user.go` to learn it is `EventUnauthorizedAccess`. Every
consumer would have to write its own name table, and they would drift from
this one.

## Design gate

- **Prior art.** `fmt.Stringer` — the standard Go way for an enum to print its
  name (`time.Month`, `time.Weekday`, `reflect.Kind`, `http.ConnState`). Any
  logger that formats values with `%v` or `Sprint` picks it up with no change
  in the caller.
- **Novice-name test.** `e.Type.String()` → `"unauthorized_access"`. No new
  concept to learn; the value simply prints as its name.
- **Complexity ledger.** +1 method on an existing exported type. +0 types,
  +0 files in the public surface beyond the method's test.
- **Where it belongs.** Here, next to the constants: only this package can keep
  the names in step with the `iota` list. A test pins that every constant has a
  name, so adding a constant without a name fails the build of the suite.
- **What it deletes.** Nothing in this repo. Consumers can drop any
  hand-written name table (none exists yet — this prevents the first one).

## Rules for this repo

- `user.go` is in the root package `auth`, which is shared with WASM builds.
  **Do not import the standard library** (`strconv`, `fmt`, `strings`) in it.
  The method is a plain `switch` returning string constants — no imports needed.
- Tests live in `tests/` (package `tests`, file header `//go:build !wasm`,
  importing `webtyp.com/auth`), like `tests/dev_autologin_test.go`.
- Names are stable identifiers (they end up in log files and may be grepped or
  alerted on): lower snake_case, never translated.

## Stage 1 — `user.go`: the method

Add, directly below the `const ( EventJWTTampered … EventDevAutologin )` block:

```go
// String returns the event's stable name (lower snake_case), so a logger
// prints "unauthorized_access" instead of 6. Names are identifiers for log
// search and alerting: never translated, never changed once published.
func (t SecurityEventType) String() string {
	switch t {
	case EventJWTTampered:
		return "jwt_tampered"
	case EventOAuthReplay:
		return "oauth_replay"
	case EventOAuthExpiredState:
		return "oauth_expired_state"
	case EventOAuthCrossProvider:
		return "oauth_cross_provider"
	case EventIPMismatch:
		return "ip_mismatch"
	case EventNonActiveAccess:
		return "non_active_access"
	case EventUnauthorizedAccess:
		return "unauthorized_access"
	case EventAccessDenied:
		return "access_denied"
	case EventPermissionCorrupt:
		return "permission_corrupt"
	case EventRateLimited:
		return "rate_limited"
	case EventInvalidRUT:
		return "invalid_rut"
	case EventUnknownRUT:
		return "unknown_rut"
	case EventSetupCompleted:
		return "setup_completed"
	case EventSetupRejected:
		return "setup_rejected"
	case EventSetupUnavailable:
		return "setup_unavailable"
	case EventDevAutologin:
		return "dev_autologin"
	}
	return "unknown"
}
```

Do NOT change `EncodeFields`: the wire format keeps `type` as an integer.

## Stage 2 — `tests/security_event_type_test.go` (new)

```go
//go:build !wasm

package tests

import (
	"testing"

	"webtyp.com/auth"
)

// Every event type prints a distinct, non-"unknown" name. Adding a constant
// without a name fails here.
func TestSecurityEventType_EveryConstantHasAName(t *testing.T) {
	seen := map[string]auth.SecurityEventType{}
	for ty := auth.EventJWTTampered; ty <= auth.EventDevAutologin; ty++ {
		name := ty.String()
		if name == "unknown" || name == "" {
			t.Errorf("SecurityEventType(%d) has no name", uint8(ty))
		}
		if prev, dup := seen[name]; dup {
			t.Errorf("name %q used by both %d and %d", name, uint8(prev), uint8(ty))
		}
		seen[name] = ty
	}
}

func TestSecurityEventType_KnownNames(t *testing.T) {
	cases := map[auth.SecurityEventType]string{
		auth.EventJWTTampered:        "jwt_tampered",
		auth.EventUnauthorizedAccess: "unauthorized_access",
		auth.EventAccessDenied:       "access_denied",
		auth.EventDevAutologin:       "dev_autologin",
	}
	for ty, want := range cases {
		if got := ty.String(); got != want {
			t.Errorf("%d.String() = %q, want %q", uint8(ty), got, want)
		}
	}
	if got := auth.SecurityEventType(250).String(); got != "unknown" {
		t.Errorf("out-of-range type = %q, want \"unknown\"", got)
	}
}
```

`EventDevAutologin` must remain the LAST constant of the block for the loop
above to cover every value. Add a one-line comment above `EventDevAutologin`'s
line only if you add new constants after it (you should not in this plan).

## Stage 3 — verify

- `go test ./...` passes.
- `GOOS=js GOARCH=wasm go vet .` passes for the root package (no stdlib import
  added to `user.go`).

## Stages

| Stage | Files | Done when |
|---|---|---|
| 1 | `user.go` | `String()` added exactly as specified |
| 2 | `tests/security_event_type_test.go` (new) | both tests pass |
| 3 | — | full suite + wasm vet green |
