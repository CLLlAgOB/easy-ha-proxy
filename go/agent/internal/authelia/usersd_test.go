package authelia

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"encoding/base64"
	"golang.org/x/crypto/argon2"
)

func TestUsersdCRUDAndLastSuperadmin(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "users_database.yml")
	_ = os.WriteFile(path, []byte("users:\n  admin:\n    displayname: Admin\n    email: a@example.com\n    password: $argon2id$v=19$x\n    disabled: false\n    groups:\n    - superadmin\n"), 0o640)
	u := NewUsersd(UsersdOptions{UsersFile: path})
	u.HashPassword = func(p string) (string, error) { return "$argon2id$fake$" + p, nil }
	call := func(raw string) map[string]any {
		r, err := u.HandleRequest(req(t, raw))
		if err != nil {
			t.Fatalf("%s: %v", raw, err)
		}
		return r
	}
	if r := call(`{"action":"delete","username":"admin"}`); r["error"] != "the last enabled superadmin cannot be deleted" {
		t.Fatalf("%v", r)
	}
	if r := call(`{"action":"update","username":"admin","fields":{"disabled":true}}`); r["error"] != "the last enabled superadmin cannot be disabled or demoted" {
		t.Fatalf("%v", r)
	}
	if r := call(`{"action":"create","username":"alice","password_plain":"correct horse","fields":{"displayname":"Alice","email":"alice@example.com","groups":["users"]}}`); r["ok"] != true {
		t.Fatalf("%v", r)
	}
	raw, _ := os.ReadFile(path)
	if !strings.HasPrefix(string(raw), "users:\n  admin:\n    disabled: false\n") || !strings.Contains(string(raw), "  alice:\n    disabled: false\n    displayname: Alice\n") {
		t.Fatalf("saved:\n%s", raw)
	}
	if r := call(`{"action":"update","username":"alice","fields":{"groups":["bad group"]}}`); r["error"] != "group name is invalid" {
		t.Fatalf("%v", r)
	}
	if r := call(`{"action":"list"}`); len(r["users"].([]any)) != 2 {
		t.Fatalf("%v", r)
	}
	if r := call(`{"action":"delete","username":"alice"}`); r["ok"] != true {
		t.Fatalf("%v", r)
	}
	if r := call(`{"action":"nope"}`); r["error"] != "unknown action: nope" {
		t.Fatalf("%v", r)
	}
}

func TestArgon2idMatchesArgon2Cffi(t *testing.T) {
	h, err := hashArgon2id("correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(h, "$")
	if len(parts) != 6 || parts[1] != "argon2id" || parts[2] != "v=19" || parts[3] != "m=65536,t=3,p=4" {
		t.Fatalf("%s", h)
	}
	salt, _ := base64.RawStdEncoding.DecodeString(parts[4])
	key := argon2.IDKey([]byte("correct horse battery"), salt, 3, 65536, 4, 32)
	if base64.RawStdEncoding.EncodeToString(key) != parts[5] || len(salt) != 16 {
		t.Fatal("hash does not verify")
	}
	if _, err := hashArgon2id("short"); err == nil || err.Error() != "The password must be 8 to 1024 characters long" {
		t.Fatalf("%v", err)
	}
}
