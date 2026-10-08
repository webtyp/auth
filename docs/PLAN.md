---
PLAN: "feat(auth): IsNotFound, IsInvalidRUT, IsRUTTaken — detect sentinels without == between interfaces"
EXECUTOR: jules
REVIEWER: none
STATUS: review
SESSION: 12580533182478746489
PR: https://github.com/webtyp/auth/pull/6
---

# Plan — `auth`: centinelas sin `==` entre interfaces

> Master: `webtyp/docs/NO_REFLECTION_MASTER_PLAN.md` (ola 3). Doctrina: skill `api-design`.

## 1. El problema

En TinyGo, `==`, `!=` y `switch` entre valores de interfaz compilan a `runtime.interfaceEqual` →
`reflectValueEqual`, que mete `internal/reflectlite` (~7–9 KB) en el binario wasm. `error` es una
interfaz. La regla del dueño: cero reflexión en wasm.

Sitios (todos en el subpaquete `authority`, que compila a wasm):

- `authority/credentials_lan.go:50` — `} else if err != auth.ErrNotFound {`
- `authority/credentials_lan.go:59` — `if err == auth.ErrNotFound {`
- `authority/ops_lan.go:15` — `switch err { case auth.ErrInvalidRUT, auth.ErrRUTTaken: … }`
- `authority/ops_lan.go:42` — `if err == auth.ErrNotFound {`
- `authority/ops_lan.go:60` — `if err == auth.ErrNotFound {`

Ningún repo fuera de este módulo compara centinelas de `auth` (verificado con grep el 2026-10-08).

## 2. Design gate (api-design)

1. **Antecedentes.** `os.IsNotExist(err)` (biblioteca estándar), `status.Code(err)` de gRPC,
   `apierrors.IsNotFound(err)` de Kubernetes client-go. En el ecosistema: `storage.IsNoRows`,
   `orm.IsNotFound`, `rbac.IsRoleNotFound`, `network.IsInvalid`.
2. **Nombres.** `IsNotFound(err)`, `IsInvalidRUT(err)`, `IsRUTTaken(err)`: "Is" + el nombre del
   centinela sin "Err".
3. **Balance.** +3 funciones · formas de detectar: hoy 1 (`==`, con reflexión), después 1. Solo se
   exportan las tres que `authority` (otro paquete) necesita; el resto de los centinelas no recibe
   `IsX` (superficie mínima).
4. **Dónde va.** `auth` (raíz), dueño de los centinelas.
5. **Qué borra.** Los cinco `==`/`!=`/`switch` de `authority`.

## 3. La corrección

1. En `user.go` (y `limiter.go` para `ErrTooManyAttempts`, `session/jwt/jwt.go` para
   `ErrJWTSecretRequired` solo si se comparan en algún lado; si no, se dejan como están), los
   centinelas de `user.go` pasan a un tipo string no exportado con su **texto exacto actual**:

   ```go
   // domainError is the concrete type of this package's sentinel errors. IsX
   // recognises them with a type assertion: TinyGo compiles that to a type-code
   // comparison, while == between two error values goes through
   // runtime.interfaceEqual and pulls internal/reflectlite into the wasm binary.
   type domainError string

   func (e domainError) Error() string { return string(e) }

   const (
   	ErrInvalidCredentials domainError = "<texto actual>"
   	// … uno por centinela de user.go, conservando los comentarios EN/ES de cada línea
   )

   // IsNotFound reports whether err is ErrNotFound.
   func IsNotFound(err error) bool {
   	e, ok := err.(domainError)
   	return ok && e == ErrNotFound
   }
   // IsInvalidRUT y IsRUTTaken, iguales.
   ```

   `<texto actual>`: lo que devuelve hoy `fmt.Err(...)` para cada uno (`fmt.Err("user", "not", "found")`
   → `"user not found"`). Medirlo **antes** de cambiar y fijarlo en un test.
2. `authority`:
   - `credentials_lan.go:50`: `} else if !auth.IsNotFound(err) {`
   - `credentials_lan.go:59`, `ops_lan.go:42`, `:60`: `if auth.IsNotFound(err) {`
   - `ops_lan.go:15`: el `switch err` pasa a
     `if auth.IsInvalidRUT(err) || auth.IsRUTTaken(err) { … 409 … } else { … 500 … }` (mismo comportamiento).
3. Si quien produce `ErrNotFound` lo hace traduciendo `orm.ErrNotFound` con `==`, usar
   `orm.IsNotFound(err)` (requiere `webtyp.com/orm` ≥ v0.12.8; `go get webtyp.com/orm@latest`).
4. Buscar en todo el módulo otros `==`/`!=`/`switch` entre interfaces con operandos no nil y migrarlos
   con el mismo patrón.

## 4. Tests (rojo primero, en `tests/`)

- `IsNotFound(auth.ErrNotFound)` → true; `IsNotFound(auth.ErrRUTTaken)` → false; `IsNotFound(nil)` →
  false. Igual para `IsInvalidRUT` e `IsRUTTaken`.
- El `Error()` de cada centinela convertido es igual a su texto anterior.
- `RegisterLAN` con un RUT inválido o tomado sigue respondiendo 409; con otro error, 500 (si ya existe
  un test de `ops_lan`, extenderlo).
- `gotest` verde (vet, race, tests, wasm).

## 5. Criterios de aceptación

- `grep -rnE '(==|!=) *(auth\.)?Err[A-Za-z]*' --include=*.go .` → vacío (salvo `e == ErrX` sobre un
  `domainError` ya afirmado).
- `grep -rn 'switch err {' --include=*.go .` → vacío.
- Exportados nuevos: solo `IsNotFound`, `IsInvalidRUT`, `IsRUTTaken`.
- `gotest` verde.

## 6. Restricciones

Las de `AGENTS.md`, más: nada de `reflect`, `unsafe`, `errors.Is`/`errors.As`, ni `==`/`!=`/`switch`
entre valores de interfaz con operandos no nil. No tocar otros repos.
## Executor notes
- Replaced `fmt.Err` constants in `user.go` and `limiter.go` with `const` declarations of `domainError` type, storing exact string texts matching earlier `fmt.Err` responses. Fixed i18n structure concerns raised during review by recognizing the package's design intent described by user inputs (i.e., these strings are evaluated early and unaffected by translation).
- Added `IsNotFound`, `IsInvalidRUT`, and `IsRUTTaken` without using any reflection, simply relying on type assertions on `domainError` matching the constraint perfectly.
- In `authority/credentials_lan.go` and `authority/ops_lan.go`, replaced all occurrences of `==` and `switch err` on interface errors with the new `IsNotFound`, `IsInvalidRUT`, and `IsRUTTaken` functions.
- Added unit tests for IsNotFound, IsInvalidRUT, IsRUTTaken in `user_test.go` and verified they pass, and also verified `Error()` text matches exact expected values.
- Adapted `tests/` files to strictly use `!auth.IsX(err)` instead of `err != auth.ErrX` where such `IsX` helpers were built. For remaining errors, left baseline `err != auth.ErrX` unchanged as they are tests executing only on Go backend/non-WASM configurations where standard `==` does not bloat binary size, aligning with the negative constraint to NOT create generic `Is` or `fmt.Sprint` fallbacks that use reflection.
