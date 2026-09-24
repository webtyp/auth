---
PLAN: "feat(auth): DEV_AUTOLOGIN — el servidor reproduce el cuerpo del formulario de login y abre una sesión real; no se compila con el tag prod"
EXECUTOR: jules
REVIEWER: none
---

> Este plan se despacha con el flujo CodeJob. Ver skill: agents-workflow.
> Orquestador (opcional, local del dueño): `~/Dev/Project/docs/MODULE_VIEWS_MASTER_PLAN.md`, fase A3.
> Todo lo que necesitas está aquí; no hace falta leer nada fuera de este repo.

# Plan — auto-login de desarrollo a nivel framework

## 1. Por qué

Toda app webtyp con login obliga al desarrollador a iniciar sesión cada vez que quiere
revisar una pantalla, y cada idle-lock o reinicio lo manda de vuelta al login. Todo
desarrollador lo necesita, así que va en el framework (este repo), no en cada app.

Decisiones del dueño (2026-09-24), cerradas:

- **Una variable: `DEV_AUTOLOGIN`.** Si existe (y no está vacía), el servidor inicia
  sesión solo. Si no existe, es producción: el comportamiento es el de hoy.
- **El valor es el cuerpo JSON exacto que envía el POST del formulario de login.** Para
  `trusted_ip`: `DEV_AUTOLOGIN={"code":"12345678-9"}`. Para `email_password`:
  `DEV_AUTOLOGIN={"email":"a@b.cl","password":"..."}`.
- **Se reproduce por el mismo camino que el login real**: la misma función hace todas
  las validaciones (límite de intentos, formato, identidad, estado del usuario, IP de
  confianza). El auto-login no puede hacer nada que un login real desde ese equipo no
  pueda. No es un bypass: es el formulario enviado por el servidor.
- **La sesión es real**: la emite la `SessionStrategy` activa (cookie normal), y RBAC
  sigue igual.
- **Con el build tag `prod` el código no se compila**: si alguien pone la variable en el
  servidor de producción, no hace nada.

## 2. Design gate

1. **Prior art.** Laravel `Auth::loginUsingId` en un seeder local, Rails
   `sign_in(user)` de Devise en `development` con un initializer, Django
   `force_login` (tests) / `django-autologin`. Los tres **saltan** la verificación de
   credenciales. Aquí se rechaza eso: el valor pasa por la misma función que el POST,
   así que la política de seguridad del servidor (IP de confianza incluida) sigue
   mandando. Vite/Next no tienen equivalente (no hacen auth).
2. **Prueba del nombre.** `DEV_AUTOLOGIN` se lee "auto-login de desarrollo". La interfaz
   `auth.FormLogin` con método `Login(ctx, body)` se lee "un autenticador cuyo login es
   un formulario; inicia sesión con este cuerpo". El evento
   `auth.EventDevAutologin` se lee solo.
3. **Contabilidad de complejidad.** Conceptos +2 (`DEV_AUTOLOGIN`, `FormLogin`).
   Archivos que la app toca para tenerlo: 0 (lo lee `authority.New`). Formas de hacer
   login: +0, porque la ruta POST y el auto-login llaman la **misma** función `Login`
   (la ruta deja de tener su propia copia de las validaciones).
4. **Dónde vive.** `auth` define la constante, la interfaz y el evento;
   `trusted_ip` y `email_password` implementan `Login`; `authority` (que ya posee la
   `SessionStrategy` y la lista de autenticadores) hace la reproducción en
   `Authenticate()`.
5. **Qué borra.** La lógica de validación dentro del closure de `r.Post(...)` en
   `trusted_ip/trusted_ip.go` y `email_password/email_password.go`: se mueve a `Login`
   y el closure queda en decodificar el resultado → escribir la respuesta.

## 3. Reglas de código (obligatorias)

- Tests con `gotest` (nunca `go test`).
- Sin strings repetidos: `EnvDevAutologin` es constante exportada; los mensajes de log
  son constantes no exportadas en `authority/devlogin.go`.
- **Preservar byte a byte las respuestas HTTP actuales** de ambas rutas de login
  (códigos y cuerpos). Los tests existentes `tests/lan_login_test.go`,
  `tests/hardening_test.go`, `tests/owasp_test.go`, `tests/limiter_test.go` y
  `tests/setup_first_admin_test.go` deben pasar **sin modificarlos**. Si uno falla, el
  refactor cambió comportamiento: corregir el refactor, no el test.
- Decodificar el cuerpo con `webtyp.com/json` (`json.Decode(input any, data
  model.Decodable) error`, ya está en `go.mod`), pasándole el `[]byte`.
- Nueva dependencia: `webtyp.com/env` (última versión publicada), para `env.Get(key
  string) string`. Solo la importa `authority/devlogin.go`.

## 4. Etapas

### Etapa 1 — contrato en el paquete `auth` (`user.go`)

Agregar:

```go
// EnvDevAutologin names the development auto-login variable. Its value is the
// exact JSON body the login form POSTs (e.g. {"code":"12345678-9"}). When it
// is set, authority replays it through the enabled authenticators' Login and
// issues a real session. Absent or empty = production behaviour. Builds with
// the "prod" tag ignore it entirely.
const EnvDevAutologin = "DEV_AUTOLOGIN"

// FormLogin is implemented by an Authenticator whose login is a form POST.
// Login runs EVERY check the POST route runs (rate limit, credential, account
// status, trusted IP) against body — the same bytes the form sends — and
// returns the user id. It never writes a response and never issues a session:
// the caller does.
type FormLogin interface {
	Login(ctx router.Context, body []byte) (userID string, err error)
}
```

Y al final del bloque de `SecurityEventType` (después de `EventSetupUnavailable`, para
no renumerar los existentes):

```go
	EventDevAutologin // authority: DEV_AUTOLOGIN opened a session (development builds only)
```

### Etapa 2 — `trusted_ip`: una sola función de login

En `trusted_ip/trusted_ip.go`:

1. Agregar el tipo no exportado:

   ```go
   // loginFailure carries the exact HTTP answer the POST route must give for a
   // rejected attempt, so Login can hold every check while the route only
   // writes.
   type loginFailure struct {
   	status int
   	body   string
   }

   func (f loginFailure) Error() string { return f.body }
   ```

2. Crear `func (a *Authenticator) Login(ctx router.Context, body []byte) (string, error)`
   con **todo** lo que hoy hace el closure de `r.Post(auth.PathLoginRUT, ...)` desde
   `ip := auth.ClientIP(...)` hasta `a.rateLimit.Reset(ip)` inclusive, en el mismo
   orden, con estos cambios:
   - `ctx.Decode(data)` → `json.Decode(body, data)`; si falla, devolver
     `loginFailure{status: 400}` (hoy: `WriteStatus(400)` sin cuerpo).
   - cada rama que hoy hace `ctx.WriteStatus(401); ctx.Write([]byte(auth.ErrInvalidCredentials.Error()))`
     → `return "", loginFailure{401, auth.ErrInvalidCredentials.Error()}`, conservando
     antes de ella las mismas llamadas a `a.notify.Notify(...)` y `a.rateLimit.Fail(ip)`.
   - al final, `return u.Id, nil`.
3. El closure de la ruta queda exactamente:

   ```go
   r.Post(auth.PathLoginRUT, func(ctx router.Context) {
   	userID, err := a.Login(ctx, ctx.Body())
   	if err != nil {
   		writeFailure(ctx, err)
   		return
   	}
   	if err := a.sessions.IssueSession(ctx, userID); err != nil {
   		ctx.WriteStatus(500)
   		return
   	}
   	ctx.SetHeader("Location", afterLogin)
   	ctx.WriteStatus(302)
   }).Public()
   ```

   con `writeFailure(ctx, err)`: si `err` es `loginFailure`, `WriteStatus(f.status)` y,
   solo si `f.body != ""`, `Write([]byte(f.body))`; cualquier otro error → `500`.
4. `var _ auth.FormLogin = (*Authenticator)(nil)`.
5. **No** tocar `mountSetup` ni `ValidateRUT`.

### Etapa 3 — `email_password`: lo mismo

En `email_password/email_password.go`, igual que la etapa 2 (mismo `loginFailure`,
mismo `writeFailure`, definidos en este paquete: son dos paquetes distintos y no se
comparten tipos no exportados). Preservar sus respuestas actuales, que **son
distintas** de las de `trusted_ip`:

- decodificación fallida → `loginFailure{400, err.Error()}`;
- límite de intentos → `loginFailure{429, err.Error()}` (el error de `a.rateLimit.Check`);
- usuario inexistente / no activo / sin identidad → `loginFailure{401, auth.ErrInvalidCredentials.Error()}`,
  **con** las mismas llamadas a `DummyCompare(...)` antes;
- contraseña incorrecta → `loginFailure{401, err.Error()}` (el error de `VerifyPassword`).

Conservar el orden actual (aquí se decodifica **antes** del límite de intentos, al
revés que `trusted_ip`). Mirar el final del closure actual (después de
`a.rateLimit.Reset(ip)`) y conservar tal cual lo que la ruta hace tras
`IssueSession`. `var _ auth.FormLogin = (*Authenticator)(nil)`.

### Etapa 4 — `authority`: la reproducción

1. `authority/module.go`, struct `Module`, agregar:

   ```go
   	devLogin       []byte      // DEV_AUTOLOGIN body; nil = production behaviour
   	devLoginFailed atomic.Bool // set after the first full rejection: never retried in this process
   ```

   (`sync/atomic`). En `New`, antes del `return`: `m.devLogin = devAutologinBody()`.

2. Nuevo `authority/devlogin.go`:

   ```go
   //go:build !prod

   package authority

   // devAutologinBody reads DEV_AUTOLOGIN. Development builds only — see
   // devlogin_prod.go for the production twin.
   func devAutologinBody() []byte {
   	v := env.Get(auth.EnvDevAutologin)
   	if v == "" {
   		return nil
   	}
   	return []byte(v)
   }
   ```

3. Nuevo `authority/devlogin_prod.go`:

   ```go
   //go:build prod

   package authority

   // devAutologinBody is always nil in production builds: DEV_AUTOLOGIN is not
   // even read, so setting it on a production server does nothing.
   func devAutologinBody() []byte { return nil }
   ```

   Este archivo **no** importa `webtyp.com/env`.

4. En `authority/devlogin.go` (el `!prod`), además:

   ```go
   const (
   	msgDevAutologinOpened   = "auth: DEV_AUTOLOGIN opened a session for user"
   	msgDevAutologinRejected = "auth: DEV_AUTOLOGIN was rejected by every enabled authenticator — showing the normal login. The value must be the exact JSON the login form POSTs, and this machine's IP must be allowed for that user. Not retried until restart."
   )

   // devAutologin replays m.devLogin through each enabled FormLogin in Enable
   // order; the first that accepts it gets a real session issued. After one
   // full rejection it never runs again in this process, so a wrong value
   // costs one rate-limit strike, not one per request.
   func (m *Module) devAutologin(ctx router.Context) string
   ```

   Algoritmo: si `m.devLoginFailed.Load()`, devolver `""`. Recorrer
   `m.authenticators`; para cada uno que implemente `auth.FormLogin`, llamar
   `Login(ctx, m.devLogin)`. Al primer `err == nil`: `m.strategy.Issue(ctx, userID)`;
   si falla, loguear el error con `m.log` y devolver `""`; si no, `m.notify(auth.SecurityEvent{Type:
   auth.EventDevAutologin, UserID: userID})`, loguear `msgDevAutologinOpened, userID` y
   devolver `userID`. Si ninguno aceptó: `m.devLoginFailed.Store(true)`, loguear
   `msgDevAutologinRejected` y devolver `""`.

   En `devlogin_prod.go`, el gemelo: `func (m *Module) devAutologin(router.Context) string { return "" }`.

5. `authority/middleware.go`, `Authenticate()`:

   ```go
   if userID, err := m.strategy.Identify(ctx); err == nil && userID != "" {
   	ctx.SetUserID(userID)
   } else if m.devLogin != nil {
   	if userID := m.devAutologin(ctx); userID != "" {
   		ctx.SetUserID(userID)
   	}
   }
   next(ctx)
   ```

   Actualizar su comentario de doc: con `DEV_AUTOLOGIN` en un build no-`prod`, una
   petición sin sesión se reproduce como login del formulario (ver `auth.EnvDevAutologin`).

### Etapa 5 — tests (`tests/dev_autologin_test.go`, nuevo)

Montar como `TestLANRUTLogin` (`tests/lan_login_test.go`): `newTestDB`, `mockPublisher`,
`CreateUser` + `RegisterLAN(u.Id, lanRUT)`, `fakeTrustedIP` con `lanTrustedIP`, y
`trustedip.New(...)`. **`t.Setenv(auth.EnvDevAutologin, ...)` va antes de
`authority.New`** (ahí se lee). Pasar peticiones por `m.Authenticate()` envolviendo un
handler que registra `ctx.UserID()`, con IP de origen controlada como en `postRUT`.

Casos:

1. **Abre sesión.** Valor `{"code":"<lanRUT>"}`, IP `lanTrustedIP`, sin cookie → el
   handler ve el `userID` de `u`, la respuesta trae la cookie de sesión, y se publicó
   `auth.EventDevAutologin`.
2. **La sesión es real.** `t.Setenv(auth.EnvDevAutologin, "")`, un segundo
   `authority.New` sobre la misma DB (ya sin auto-login), y una petición con la cookie
   del caso 1 → identifica al mismo usuario.
3. **Misma política que el login real.** Mismo valor, IP `10.0.0.7` → anónimo, y se
   publicó `auth.EventIPMismatch` (lo publica `Login`, no un camino aparte).
4. **No reintenta.** Tras el caso 3, envolver el autenticador en un fake que implemente
   `auth.FormLogin` y cuente llamadas; dos peticiones más → el contador sigue en 0.
5. **Sin variable = hoy.** `t.Setenv(auth.EnvDevAutologin, "")` → anónimo, sin cookie,
   sin eventos.
6. **Primero que acepta, en orden de `Enable`.** Habilitar `email_password` y después
   `trusted_ip`; valor `{"code":"<lanRUT>"}` → entra por `trusted_ip`.

### Etapa 6 — build de producción

Verificación, no test (gotest no pasa tags): `go build -tags prod ./...` y
`go vet -tags prod ./...` compilan limpio, y
`go list -tags prod -deps ./authority | grep webtyp.com/env` → vacío.

### Etapa 7 — documentación

`README.md`, nueva sección **"Development auto-login"** (en inglés, como el README):
qué es `DEV_AUTOLOGIN`, que el valor es el JSON del formulario (con los dos ejemplos de
§1), que pasa por las mismas validaciones (la IP del equipo tiene que estar habilitada),
que tras cerrar sesión la siguiente petición vuelve a entrar sola (para ver la pantalla
de login, quitar la variable y reiniciar), y que `-tags prod` la elimina. Agregar
`EventDevAutologin` a la tabla de eventos de `docs/ARCHITECTURE.md` si existe una.

## 5. Verificación

```bash
gotest                                   # verde, incluidos los tests existentes sin tocar
go build -tags prod ./... && go vet -tags prod ./...
grep -n 'ctx.Decode' trusted_ip/trusted_ip.go email_password/email_password.go   # vacío
```

## 6. Tabla de etapas

| # | Etapa | Archivos |
|---|---|---|
| 1 | `EnvDevAutologin`, `FormLogin`, `EventDevAutologin` | `user.go` |
| 2 | `trusted_ip.Login` + ruta delgada | `trusted_ip/trusted_ip.go` |
| 3 | `email_password.Login` + ruta delgada | `email_password/email_password.go` |
| 4 | reproducción en `Authenticate` | `authority/module.go`, `authority/middleware.go`, `authority/devlogin.go`, `authority/devlogin_prod.go`, `go.mod` |
| 5 | tests | `tests/dev_autologin_test.go` |
| 6 | build prod | — |
| 7 | docs | `README.md`, `docs/ARCHITECTURE.md` |
