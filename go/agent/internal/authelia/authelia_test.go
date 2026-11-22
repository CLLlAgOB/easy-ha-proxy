package authelia

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestBansdProtocolAndValidation(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "bans.sh")
	_ = os.WriteFile(script, []byte("#!/bin/sh\necho \"ok:$1:$2\"\n"), 0o755)
	sock := filepath.Join(dir, "bansd.sock")

	srv := NewBansdServer(BansdOptions{
		SocketPath:      sock,
		ScriptPath:      script,
		CommandTimeout:  5 * time.Second,
		MaxRequestBytes: 8192,
		MaxWorkers:      2,
	})
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.Serve(ctx, ln) }()

	call := func(req map[string]any) map[string]any {
		t.Helper()
		c, err := net.Dial("unix", sock)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer c.Close()
		b, _ := json.Marshal(req)
		_, _ = c.Write(append(b, '\n'))
		line, err := bufio.NewReader(c).ReadString('\n')
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		var out map[string]any
		_ = json.Unmarshal([]byte(line), &out)
		return out
	}

	if res := call(map[string]any{"action": "ping"}); res["ok"] != true || res["pong"] != true {
		t.Fatalf("ping failed: %+v", res)
	}
	if res := call(map[string]any{"action": "list"}); res["ok"] != true {
		t.Fatalf("list failed: %+v", res)
	}
	if res := call(map[string]any{"action": "revoke-user", "username": "../root"}); res["ok"] != false {
		t.Fatalf("invalid username must be rejected: %+v", res)
	}
	if res := call(map[string]any{"action": "revoke-ip", "ip": "203.0.113.0/24"}); res["ok"] != true {
		t.Fatalf("valid CIDR revoke-ip failed: %+v", res)
	}
	if res := call(map[string]any{"action": "revoke-ip", "ip": "not-an-ip"}); res["ok"] != false {
		t.Fatalf("invalid IP must be rejected: %+v", res)
	}
}

func TestUsersdCRUDAndLastSuperadminGuard(t *testing.T) {
	dir := t.TempDir()
	usersFile := filepath.Join(dir, "users_database.yml")
	_ = os.WriteFile(usersFile, []byte("users:\n  admin:\n    displayname: 'Admin'\n    email: 'a@example.com'\n    password: '$argon2id$v=19$hash'\n    disabled: false\n    groups:\n      - superadmins\n"), 0o600)

	srv := NewUsersdServer(UsersdOptions{UsersFile: usersFile})
	srv.HashFunc = func(_ context.Context, plain string) (string, error) {
		return "$argon2id$fake$" + plain, nil
	}

	// Cannot delete or disable the last enabled superadmin.
	if res := srv.HandleRequest(context.Background(), map[string]any{"action": "delete", "username": "admin"}); res["ok"] != false {
		t.Fatalf("must refuse deleting last superadmin: %+v", res)
	}
	if res := srv.HandleRequest(context.Background(), map[string]any{"action": "update", "username": "admin", "disabled": true}); res["ok"] != false {
		t.Fatalf("must refuse disabling last superadmin: %+v", res)
	}

	// Create a second user, update it, then delete it cleanly.
	if res := srv.HandleRequest(context.Background(), map[string]any{
		"action": "create", "username": "alice", "password_plain": "pw123",
		"displayname": "Alice", "email": "alice@example.com", "groups": []any{"users"},
	}); res["ok"] != true {
		t.Fatalf("create alice failed: %+v", res)
	}
	if res := srv.HandleRequest(context.Background(), map[string]any{"action": "list"}); res["ok"] != true || len(res["users"].([]map[string]any)) != 2 {
		t.Fatalf("list failed: %+v", res)
	}
	if res := srv.HandleRequest(context.Background(), map[string]any{"action": "delete", "username": "alice"}); res["ok"] != true {
		t.Fatalf("delete alice failed: %+v", res)
	}
}

func TestConfigdPeerUIDAndMailRedaction(t *testing.T) {
	dir := t.TempDir()
	mailFile := filepath.Join(dir, "mail-notify.json")
	notifFile := filepath.Join(dir, "notification.txt")
	_ = os.WriteFile(mailFile, []byte(`{"enabled":true,"from":"gw@example.com","smtp_password":"secret"}`), 0o600)
	_ = os.WriteFile(notifFile, []byte("reset link: https://example.com/tok"), 0o600)

	srv := NewConfigdServer(ConfigdOptions{
		MailStatePath:    mailFile,
		NotificationFile: notifFile,
		AllowedNotifUID:  0,
	})

	// Non-root peer cannot reveal or handle local notification file.
	if res := srv.HandleRequest(context.Background(), map[string]any{"action": "notification_reveal"}, 1000); res["forbidden"] != true {
		t.Fatalf("expected forbidden for non-root peer: %+v", res)
	}
	// Root peer can reveal and clear it.
	if res := srv.HandleRequest(context.Background(), map[string]any{"action": "notification_reveal"}, 0); res["ok"] != true {
		t.Fatalf("expected root reveal to succeed: %+v", res)
	}
	if res := srv.HandleRequest(context.Background(), map[string]any{"action": "notification_handle"}, 0); res["ok"] != true {
		t.Fatalf("expected root handle to succeed: %+v", res)
	}
	// mail_view redacts smtp_password.
	mv := srv.HandleRequest(context.Background(), map[string]any{"action": "mail_view"}, 1000)
	if mv["ok"] != true || mv["mail"].(map[string]any)["smtp_password"] != "***" {
		t.Fatalf("expected redacted smtp_password: %+v", mv)
	}
}
