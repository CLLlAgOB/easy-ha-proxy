package contract

import "testing"

// Regression tests for versioned static URLs: the app appends a content
// version to every url_for('static', ...) so released assets can be cached
// immutably. One caller builds a *directory* URL and appends the file name
// in JavaScript, so versioning a directory would move the query string in
// front of the file name and break those requests.
//
// The Python module also defined a load_static_version helper that executed
// the app factory's Python helper; no test in the module called it, so there
// is nothing of it to port.

// The flag base must stay a directory URL: this documents the shape the
// versioning helper must tolerate.
func TestFlagBaseIsStillADirectoryURL(t *testing.T) {
	base := read(t, webDir+"/templates/base.html")
	mustContain(t, base, "HAPROXY_ADMIN_FLAG_BASE", "base.html")
	mustContain(t, base, "flags/4x3/", "base.html")
}
