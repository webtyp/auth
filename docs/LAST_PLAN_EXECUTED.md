# Plan: el inicio de sesión como una sola pieza (D75, D76, D77)

> Ejecución local, repo por repo, con `replace` hacia las copias locales; nada se publica hasta que el dueño revise.
> Decisiones: `webtyp/docs/ARCHITECTURE_MASTER_PLAN.md` D75–D77. Grafo y reglas: skill **sign-in-and-permissions**.
> Flujo: [diagrams/SIGN_IN.md](diagrams/SIGN_IN.md).
> Decididas también D78 (cada modo decide si se muestra en esta puerta), D79 (un solo registro de equipos), D80 (sin modos
> = sin inicio de sesión) y D81 (primer administrador con passkey por código de un solo uso). D82: cada modo crea sus
> propias tablas (`auth.ModeWithTables`). Incluye O2 de `webtyp/docs/SECURITY_OBSERVABILITY_MASTER_PLAN.md`
> (etapa 4b: `auth` informa con `securityevent` v0.0.2). Sin preguntas abiertas; espera la revisión del dueño (🔵).

## Ecosystem search

- Contrato de un modo: **reutilizar** `auth.Authenticator` (`auth/user.go:218`); se agrega solo cómo se arma (`auth.Mode`).
- Puertos: **reutilizar** `IdentityStore`, `SessionIssuer`, `SecurityNotifier`, `ProviderRegistry`, `TrustedIPStore` (`auth/user.go:269-333`) y `passkey.Sessions` (`passkey/passkey.go:51`); `Ports` solo los agrupa.
- Primer administrador: **mover** `seedFirstAdmin` de `appkit/backend/signin.go:73` (es común a todo modo, no de `trusted_ip`).
- «Quién soy»: **reutilizar** la lectura crud `me` hecha en local (P60: `authority/rule_me_read.go`).
- Pantalla de cada modo: **mover** los formularios de RUT de `appkit/browser/signin.go` a `auth/trusted_ip/browser`; `passkey/browser` ya existe.

## Design gate

1. **Prior art** (documentación oficial leída el 2026-11-18):
   - [Better Auth](https://www.better-auth.com/docs/concepts/plugins): `betterAuth({ plugins: [passkey()] })`; el núcleo da a cada plugin la base y las sesiones (`ctx.context`); cada método trae mitad de servidor y de cliente (`passkeyClient()`, [passkey](https://www.better-auth.com/docs/plugins/passkey)).
   - [Auth.js](https://authjs.dev/getting-started/authentication/webauthn): `providers: [Passkey]`; el adaptador de base se declara una vez y ningún proveedor lo recibe.
   - [ASP.NET Core](https://learn.microsoft.com/en-us/aspnet/core/security/authentication/?view=aspnetcore-9.0): `AddAuthentication().AddCookie(o => …).AddJwtBearer(o => …)`; cada esquema = opciones + manejador; el servicio central no conoce esquemas.
   Los tres: la app lista valores de opciones; el núcleo da a cada modo lo que necesita; el núcleo no conoce modos. Igual aquí.
2. **Nombres:** `auth.Mode` («un modo de entrada»), `Mode.Build(Ports)` («armar el modo con las piezas»), `auth.Ports`, `Ports.MakeAdmin` («hacer administrador»), `trustedip.Mode{Devices}`, `passkey.Mode{Origin}`, `view.User` con `Can`, `view.Session.SignOut`, `view.Session.Entries`.
3. **Ledger:** conceptos +2 (`Mode`, `Ports`) −2 (`SignInMethod`, `SignInByTrustedIP`) · archivos que toca la app para cambiar de modo: 4 → 1 · líneas en la app: igual (1 por modo) · formas de hacer lo mismo: −1 (el enum desaparece).
4. **Dónde:** `Mode`/`Ports` en `auth` (el dueño del contrato); lo de RUT en `trusted_ip`; el primer administrador en `appkit` solo como `MakeAdmin` (une `access` y `rbac`, que `auth` no conoce); `view.User` en `view` (contrato entre `appkit` y `layout`, sin importar `auth`).
5. **Borra:** en `auth`: `ProfileDTO`, `Grant`/`Can`, `RememberSession`/`RememberedSession`, `ShellProfile` (sin consumidores fuera de sus pruebas) y `LoginLAN` (solo lo usan pruebas: se borra, no se mueve); `appkit.SignInMethod`, `SignInByTrustedIP`, `ErrUnknownSignIn`, `appkit/backend/signin.go` (salvo `MakeAdmin`), `appkit/browser/signin.go`, `staffDevices`, `refuseAllIPs`, `meGrant`; en `authority`: `credentials_lan.go`, `lan_store.go`, `credentials_password.go` y sus imports de modos; en `layout/app/browser.go`: `pathSetup`, `pathLogout`, `opMe`, `profileDTO`, `profileIdentity`; `view.EntryScreens{Login, Setup}`.

## Etapas

| # | Repo | Qué | Verificación |
|---|---|---|---|
| 1 | `auth`, `appkit`, `layout` | `diagrams/SIGN_IN.md` con D76, D78, D80, D81 y D82; antes del código, las pruebas rojas de cada rama, cada una en la librería dueña (**testing**): `auth` (`me`, estados de `/setup`, salir, cada modo), `appkit` (armar los modos con `Ports`; sin modos arranca y avisa; `trustedip.Mode` sin `Devices` no arranca), `layout` (pantallas de entrada, aviso de servidor caído), con un modo falso en el borde | las pruebas existen y fallan por lo que falta |
| 2 | `auth` | `auth.Mode` + `auth.Ports` (`Identities`, `Registry`, `Sessions`, `StepUp`, `Principal`, `Notify`, `DB`, `IDs`, `MakeAdmin`, `Built`); `authority.Ports()` llena los suyos y `appkit` agrega `MakeAdmin` y `Built` (`backend.FindBuiltModule`, `appkit/backend/backend.go:103`); `appkit` llama `Mode.Build(ports)` y entrega el resultado a `authority.Enable(...auth.Authenticator)`, que no cambia. `Ports.DB` es `*orm.DB` (lo pide `passkey.New`): la raíz de `auth` pasa a importar `orm` | `gotest` |
| 3 | `auth` | `trusted_ip` es dueño del RUT: `RegisterLAN`/`UnregisterLAN` pasan a `trusted_ip` (la relación RUT ↔ usuario sigue siendo una `Identity` de proveedor `trusted_ip`); se borran `lanip` y `lan_identity` (D79); `trustedip.Mode{Devices model.ModuleDefinition}` busca el registro de equipos con `Ports.Built` y usa `Ports.MakeAdmin`; `/setup` 200 `{required:false}` / 503 (D76a) | `gotest`; `grep -rn "auth/trusted_ip\|auth/email_password" auth/authority` vacío |
| 4 | `auth` | `email_password` es dueño del hash (sale `credentials_password.go`); `passkey.Mode{Origin}`; primer administrador por código de un solo uso escrito en el registro mientras no haya administrador (D81), con su pantalla en `passkey/browser`; `passkey` cumple `auth.ModeWithTables` (D82); `oauth2/provider/microsoft` deja de importar `google` (ayudante común en `oauth2`) | `gotest` |
| 4b | `auth`, `appkit` | O2: cada modo y `authority` informan con `securityevent.Reporter` (`go get webtyp.com/securityevent@v0.0.2`); los 22 `auth.SecurityEventType` pasan a sus `securityevent.Kind` (RUT inválido o desconocido, IP no registrada, cuenta inactiva, passkey o aserción rechazada → `LoginFailed` con su `Reason`; JWT alterado → `TokenForged`; estado OAuth reusado → `TokenReused`; sesión inválida → `SessionInvalid`; primer administrador → `AdminCreated`; setup tras existir → `SetupRejected`; registro ilegible → `SecurityStoreFailed`; passkey registrada o borrada → `CredentialAdded`/`CredentialRemoved`; ingreso correcto → `LoginSucceeded`); se borran `SecurityEventType`, `SecurityEvent`, `TopicSecurity` y `SecurityNotifier`; `Ports.Notify` pasa a `Ports.Report securityevent.Reporter`; `appkit` cambia `securityEventLogger` por `securityevent.Listen` | `gotest`; `grep -rn "SecurityEventType\|TopicSecurity" auth appkit` vacío |
| 5 | `view` | `view.User{ID, Name, Avatar string; Grants []model.Grant}` + `Can(resource, action)`; `Session.User`, `Session.SignOut func()`, `Session.Entries []Entry` (una por modo); `view.EntryScreen` (interfaz chica que un modo cumple para dar su pantalla) | `gotest` |
| 6 | `auth` | pantallas (cada una pregunta a su ruta si está abierta en esta puerta, D78): `trusted_ip/browser` (formularios de RUT y primer administrador, movidos de `appkit/browser/signin.go`) y `passkey/browser` cumplen `view.EntryScreen`; `authority` da la lectura de `me` y la salida para el navegador | `gotest` |
| 7 | `appkit` | `App.SignIn []auth.Mode`; arma `authority`, `Ports`, recorre la lista; `MakeAdmin` (rol `admin` con `access` + `rbac`); el permiso de `me` lo declara `authority.DefaultGrants` y `appkit` lo aplica junto a los de `Backend.Modules` (`authority` no está en esa lista); `appkitc` genera la migración que recorre `App.SignIn` y llama `Migrate` de cada modo con tablas (D82); en el navegador llena `Session.User`, `SignOut`, `Entries` (sin nombrar modos); borra lo de la fila 5 del gate | `gotest`; `grep -rn "trusted_ip\|SignInBy" appkit` vacío |
| 8 | `layout` | dibuja con `view.Session`: sin sesión, las pantallas de `Entries`; servidor caído, el aviso de D76b; borra lo de la fila 5 del gate | `gotest`; `grep -rn '"/setup"\|"/logout"\|opMe' layout` vacío |
| 9 | `veltylabs/mjosefa-cms` | `config/app.go`: `SignIn: []auth.Mode{trustedip.Mode{Devices: staffmanager.Definition}}` (la passkey, cuando se configure la segunda puerta); `migrate/pastdb/staff.go` usa la API movida de `RegisterLAN` | `webtyp dev`: acceso por RUT, primer administrador, salir, sin 404 en la consola |
| 10 | `auth`, `appkit`, `view`, `layout`, `devskills` | docs (README, ARCHITECTURE, diagramas) y la skill **sign-in-and-permissions** sin los 🔴 corregidos; `framework-map`: `auth` y `appkit` pasan a 🟢 | lectura del dueño |

Publicación (tras la revisión del dueño): `view` → `auth` (con `securityevent` v0.0.2 ya publicado) → `appkit` → `layout` → `mjosefa-cms`, con `gopush` en cascada.

## Fuera de este plan

Borrar los modos que el framework no usa (`email_password`, `cfaccess`, y `oauth2`/`local`/`clientassertion` que solo usa `iam`): pregunta aparte, `iam` se rompe.
