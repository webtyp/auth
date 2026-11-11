package tests

import (
	"webtyp.com/auth"
	"webtyp.com/auth/authority"
)

// rowOf is the stored model of a contract session: the two types have the same fields, so a conversion is enough.
func rowOf(s auth.Session) *authority.Session {
	r := authority.Session(s)
	return &r
}
