package server

import (
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	if os.Getenv("HAPROXY_ADMIN_TEMPLATES_DIR") == "" {
		_ = os.Setenv("HAPROXY_ADMIN_TEMPLATES_DIR", "../../../../docker/app/haproxy_admin/templates")
	}
	os.Exit(m.Run())
}
