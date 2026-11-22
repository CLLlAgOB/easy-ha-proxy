package ui

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"easy-ha-proxy/panel/internal/i18n"
	"easy-ha-proxy/panel/internal/security"
)

func TestAll22ProductionTemplatesCompileAndRenderExactDOM(t *testing.T) {
	cat, _ := i18n.LoadDir("", "en")
	r, err := NewRenderer("", "UTC", cat)
	if err != nil {
		t.Fatalf("NewRenderer failed: %v", err)
	}

	checks := []struct {
		template string
		wantDOM  []string
	}{
		{"index.html", []string{`id="sites-list"`, `id="ban"`, `id="unban-form"`, `id="whitelist-form"`, `id="ip-auth"`, `js/dashboard.js`}},
		{"health.html", []string{`window.HA_IS_SUPERADMIN = true`, `id="tblSystemd"`, `id="tblDocker"`, `id="tblRecent"`, `js/health.js`}},
		{"monitoring.html", []string{`id="mon-ranges"`, `data-range="24h"`, `class="mon-expand"`, `js/monitoring.js`}},
		{"live_activity.html", []string{`data-window="60"`, `js/live_activity.js`}},
		{"alerts.html", []string{`id="al-active-body"`, `id="al-history-body"`, `id="al-rules-body"`, `js/alerts.js`}},
		{"audit.html", []string{`id="au-range"`, `id="au-body"`, `js/audit.js`}},
		{"haproxy_backends.html", []string{`id="rt-list"`, `data-superadmin="1"`, `js/haproxy_backends.js`}},
		{"haproxy_geoip.html", []string{`id="geoip-db-status"`, `id="geoip-countries-form"`, `js/geoip.js`}},
		{"config_history.html", []string{`id="ch-list"`, `id="ch-diff"`, `js/config_history.js`}},
		{"dns_providers.html", []string{`id="dp-list"`, `value="cloudflare"`, `js/dns_providers.js`}},
		{"cert_delivery.html", []string{`id="cd-body"`, `value="sftp"`, `js/cert_delivery.js`}},
		{"trash.html", []string{`id="tr-body"`, `max="365"`, `js/trash.js`}},
		{"adaptive_protection.html", []string{`data-weight="SCANNER_PATH"`, `js/adaptive_protection.js`}},
		{"adaptive_bans.html", []string{`id="ap-bans"`, `js/adaptive_bans.js`}},
		{"adaptive_ban_detail.html", []string{`id="ab-detail"`, `js/adaptive_ban_detail.js`}},
		{"detection_rules.html", []string{`js/detection_rules.js`, `js/detection_context.js`}},
		{"request_log.html", []string{`js/request_log.js`}},
		{"system_schedule.html", []string{`id="schedule-app"`, `id="plan-timeline"`, `js/system_schedule.js`}},
		{"ssh_security.html", []string{`data-status-url="/system/ssh-security/api/status"`, `id="ssh-state"`, `js/ssh_security.js`}},
		{"os_security.html", []string{`data-status-url="/system/os-security/api/status"`, `id="oss-start"`, `00:00`, `js/os_security.js`}},
		{"system_updates.html", []string{`data-status-url="/system/updates/api/status"`, `js/system_updates.js`}},
		{"system_backups.html", []string{`data-upload-url="/system/backups/api/uploads"`, `8.0 GiB`, `js/system_backups.js`}},
	}

	for _, tc := range checks {
		if !r.HasPageTemplate(tc.template) {
			t.Fatalf("missing compiled template %s", tc.template)
		}
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req = req.WithContext(security.WithIdentity(req.Context(), &security.Identity{
			User:         "rootadmin",
			IsSuperadmin: true,
			CSPNonce:     "nonce123",
			CSRFToken:    "csrf123",
		}))
		rec := httptest.NewRecorder()
		r.Render(rec, req, PageSpec{Template: tc.template, PageID: tc.template})
		if rec.Code != http.StatusOK {
			t.Fatalf("render %s returned %d: %s", tc.template, rec.Code, rec.Body.String())
		}
		body := rec.Body.String()
		for _, want := range tc.wantDOM {
			if !strings.Contains(body, want) {
				t.Errorf("template %s missing expected fragment %q", tc.template, want)
			}
		}
	}
}
