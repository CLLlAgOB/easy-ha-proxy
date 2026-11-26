package contract

import (
	"regexp"
	"testing"
)

// Regression check for the TCP proxy edit action: the list must offer an
// explicit Edit button linking to the edit route for each proxy, so editing
// is reachable from the interface rather than only by URL.

func TestTcpListHasAnExplicitEditButton(t *testing.T) {
	template := read(t, webDir+"/templates/haproxy_tcp.html")
	editButton := regexp.MustCompile(`(?s)<a class="btn btn-small"\s+href="\{\{ url_for\('routes\.haproxy_tcp_edit', name=t\.name\) \}\}">\s*Edit\s*</a>`)
	if !editButton.MatchString(template) {
		t.Error("haproxy_tcp.html has no explicit Edit button linking to routes.haproxy_tcp_edit")
	}
}
