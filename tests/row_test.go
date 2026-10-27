package tests

import (
	"testing"
	"webtyp.com/auth"
	"webtyp.com/model"
)

func TestRowsDeclaredOnFields(t *testing.T) {
	u := auth.User{Id: "1", Name: "User One", Email: "u1@test.com"}
	row := model.RowOf(&u)
	if row.ID != "1" || row.Title != "User One" || row.Detail != "u1@test.com" {
		t.Fatalf("wrong row: %+v", row)
	}
}
