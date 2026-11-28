package app

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"easy-ha-proxy/panel/internal/config"
	"easy-ha-proxy/panel/internal/security"
)

func TestFlashSessionCookieIsolatedAcrossUserSwitch(t *testing.T) {
	a := &App{Cfg: &config.Config{SessionSecure: false}, secret: []byte("test-secret")}

	// Alice flashes a message and gets a signed flask session cookie.
	w1 := httptest.NewRecorder()
	r1 := httptest.NewRequest(http.MethodGet, "/", nil)
	c1 := &Ctx{App: a, W: w1, R: r1, ID: &security.Identity{User: "alice"}}
	c1.Flash("secret for alice", "info")
	c1.commitCookies()
	var ck *http.Cookie
	for _, c := range w1.Result().Cookies() {
		if c.Name == sessionCookie {
			ck = c
		}
	}
	if ck == nil {
		t.Fatal("expected flash session cookie for alice")
	}

	// Bob presents alice's cookie in the same browser: must NOT see alice's flash.
	r2 := httptest.NewRequest(http.MethodGet, "/", nil)
	r2.AddCookie(ck)
	c2 := &Ctx{App: a, W: httptest.NewRecorder(), R: r2, ID: &security.Identity{User: "bob"}}
	if got := c2.popFlashes(); len(got) != 0 {
		t.Fatalf("bob received alice's flashes after user switch: %+v", got)
	}

	// Alice herself still sees her flash.
	r3 := httptest.NewRequest(http.MethodGet, "/", nil)
	r3.AddCookie(ck)
	c3 := &Ctx{App: a, W: httptest.NewRecorder(), R: r3, ID: &security.Identity{User: "alice"}}
	if got := c3.popFlashes(); len(got) != 1 || got[0].Message != "secret for alice" {
		t.Fatalf("alice did not receive her own flash: %+v", got)
	}
}

func TestReadBoundedBodyLimitsAndIncompleteDetection(t *testing.T) {
	okResp := &http.Response{
		ContentLength: 5,
		Body:          io.NopCloser(strings.NewReader("hello")),
	}
	got, err := readBoundedBody(okResp, 16)
	if err != nil || string(got) != "hello" {
		t.Fatalf("expected ok body, got %q err=%v", string(got), err)
	}

	overResp := &http.Response{
		ContentLength: 32,
		Body:          io.NopCloser(bytes.NewReader(bytes.Repeat([]byte("a"), 32))),
	}
	if _, err := readBoundedBody(overResp, 16); err == nil {
		t.Fatal("expected oversized response error")
	}

	truncResp := &http.Response{
		ContentLength: 10,
		Body:          io.NopCloser(strings.NewReader("short")),
	}
	if _, err := readBoundedBody(truncResp, 16); err == nil {
		t.Fatal("expected incomplete response error")
	}
}

func TestSocketPathFallbacksHonorLegacyEnvVars(t *testing.T) {
	t.Setenv("EASY_HA_PROXY_BACKUPD_SOCKET", "")
	t.Setenv("BACKUPD_SOCKET_PATH", "/tmp/alt-backupd.sock")
	if got := backupdSocketPath(); got != "/tmp/alt-backupd.sock" {
		t.Fatalf("backupdSocketPath = %q", got)
	}

	t.Setenv("EASY_HA_PROXY_UPDATED_SOCKET", "")
	t.Setenv("UPDATED_SOCKET_PATH", "/tmp/alt-updated.sock")
	if got := updatedSocketPath(); got != "/tmp/alt-updated.sock" {
		t.Fatalf("updatedSocketPath = %q", got)
	}
}

func TestStartTrashPurgerStopsOnContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	StartTrashPurger(ctx)
	cancel()
	time.Sleep(20 * time.Millisecond)
}
