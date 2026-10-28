package tests

import (
	"testing"
	"webtyp.com/auth"
)

func TestItemsDeclaredOnFields(t *testing.T) {
	u := auth.User{Id: "1", Name: "User One", Email: "u1@test.com"}
	item := u.Item()
	if item.ID != "1" || item.Label != "User One" || item.Description != "u1@test.com" {
		t.Fatalf("wrong item: %+v", item)
	}
}
