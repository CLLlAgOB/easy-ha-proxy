package config

import (
	"path/filepath"
	"testing"
)

func TestDefaultsMatchRuntimeConventions(t *testing.T) {
	t.Setenv("HAPROXY_ADMIN_SECRET_KEY", "test-secret-key")
	t.Setenv("HAPROXY_ADMIN_SECRET_FILE", filepath.Join(t.TempDir(), "secret_key"))
	t.Setenv("WHITELIST_GLOBAL_FILE", "")
	t.Setenv("WHITELIST_GEO_FILE", "")
	t.Setenv("HAPADM_BAN_TABLE", "")
	t.Setenv("EASY_HA_PROXY_BACKUPD_SOCKET", "")
	t.Setenv("BACKUPD_SOCKET_PATH", "/custom/backupd.sock")
	t.Setenv("EASY_HA_PROXY_UPDATED_SOCKET", "")
	t.Setenv("UPDATED_SOCKET_PATH", "/custom/updated.sock")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if cfg.WhitelistGlobal != "/etc/haproxy/whitelist.ip" {
		t.Fatalf("WhitelistGlobal = %q", cfg.WhitelistGlobal)
	}
	if cfg.WhitelistGeo != "/etc/haproxy/geoip/whitelist.geo" {
		t.Fatalf("WhitelistGeo = %q", cfg.WhitelistGeo)
	}
	if cfg.BanTable != "tbl_ban" {
		t.Fatalf("BanTable = %q", cfg.BanTable)
	}
	if cfg.BackupdSocket != "/custom/backupd.sock" {
		t.Fatalf("BackupdSocket = %q", cfg.BackupdSocket)
	}
	if cfg.UpdatedSocket != "/custom/updated.sock" {
		t.Fatalf("UpdatedSocket = %q", cfg.UpdatedSocket)
	}
}
