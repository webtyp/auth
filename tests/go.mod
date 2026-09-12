// Separate test module: isolates the real-database test deps (webtyp.com/sqlite
// and its modernc.org/* driver tree) so the root webtyp.com/auth module is not
// forced to carry them.
//
// The suite runs against real SQLite on purpose, not storage/mem: the properties
// under test here ARE database semantics — a UNIQUE email, two NULL emails that
// must not collide on that index, session expiry, transactional isolation.
// storage/mem enforces no constraints and ignores the SQL string it is handed,
// so those assertions would pass without testing anything. That divergence is
// not hypothetical: it is what hid the NULL-scan defect fixed by the
// NULLABLE_COLUMNS wave.
//
// gotest runs submodule directories that ./... does not reach, and since
// devflow v0.4.92 it merges their coverage profiles into the reported figure,
// so this split costs neither coverage nor an accurate number. On older gotest
// the percentage collapses to what the root packages' own tests cover (~1%);
// the real figure is always available directly:
//
//	cd tests && go test -coverpkg=webtyp.com/auth/... ./...
module webtyp.com/auth/tests

go 1.25.2

replace webtyp.com/auth => ..

require (
	modernc.org/sqlite v1.58.0
	webtyp.com/auth v0.0.47
	webtyp.com/crypto v0.0.27
	webtyp.com/ddl v0.0.17
	webtyp.com/events v0.0.5
	webtyp.com/form v0.4.12
	webtyp.com/json v0.5.26
	webtyp.com/jwt v0.1.20
	webtyp.com/model v0.1.9
	webtyp.com/orm v0.12.3
	webtyp.com/router v0.1.38
	webtyp.com/server v0.2.55
	webtyp.com/sqlite v0.3.7
	webtyp.com/unixid v0.2.28
	webtyp.com/user v0.3.13
	webtyp.com/view v0.5.10
)

require (
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/mattn/go-isatty v0.0.24 // indirect
	github.com/ncruces/go-strftime v1.0.0 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	github.com/smallstep/truststore v0.13.0 // indirect
	golang.org/x/crypto v0.55.0 // indirect
	golang.org/x/net v0.57.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/text v0.41.0 // indirect
	howett.net/plist v1.0.0 // indirect
	modernc.org/libc v1.75.6 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.12.1 // indirect
	webtyp.com/base64 v0.0.6 // indirect
	webtyp.com/dom v0.13.14 // indirect
	webtyp.com/fetch v0.1.28 // indirect
	webtyp.com/fmt v1.0.0 // indirect
	webtyp.com/input v0.0.8 // indirect
	webtyp.com/sqlt v0.0.10 // indirect
	webtyp.com/storage v0.0.9 // indirect
	webtyp.com/time v0.5.6 // indirect
	webtyp.com/widget v0.6.29 // indirect
)
