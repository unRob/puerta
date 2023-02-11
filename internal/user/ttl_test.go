package user_test

import (
	"fmt"
	"testing"

	"git.rob.mx/nidito/puerta/internal/user"
)

func TestParse(t *testing.T) {
	ttl := user.TTL{}
	err := ttl.Scan("")
	if err != nil {
		t.Fatalf("Failed scanning empty string: %s", err)
	}

	err = ttl.Scan("7d")
	if err != nil {
		t.Fatalf("Failed scanning 7d: %s", err)
	}

	if ttl.Seconds() != 604800 {
		t.Fatalf("parsed bad seconds %d", ttl.Seconds())
	}

	// conn := sqlite.ConnectionURL{
	// 	Database: "test.db",
	// 	Options: map[string]string{
	// 		"_journal":      "WAL",
	// 		"_busy_timeout": "5000",
	// 	},
	// }

	// _db, err := sqlite.Open(conn)
	// if err != nil {
	// 	t.Fatal(err)
	// }

	// user := &user.User{}
	// if err := _db.Get(user, db.Cond{"handle": "test"}); err != nil {
	// 	t.Fatalf("could not get user: %s", err)
	// }

	// t.Fatalf("user ttl (%v): %d, from now: %s", user.TTL, user.TTL.Seconds(), user.TTL.FromNow())

}

func TestMarshalDB(t *testing.T) {
	ttl := user.TTL{}

	err := ttl.Scan("7d")
	if err != nil {
		t.Fatalf("Failed scanning 7d: %s", err)
	}

	if ttl.Seconds() != 60*60*24*7 {
		t.Fatalf("parsed bad seconds %d", ttl.Seconds())
	}

	data, err := ttl.MarshalDB()
	if err != nil {
		t.Fatalf("could not marshal ttl %s", err)
	}

	expected := `"7d"`
	if fmt.Sprintf("%s", data) != expected {
		t.Fatalf("encoded data mismatch. expected %s, got %s", expected, data)
	}
}
