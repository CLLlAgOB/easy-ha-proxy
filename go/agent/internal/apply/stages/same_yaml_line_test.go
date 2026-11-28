package stages

import "testing"

// The panel's YAML dump writes the socket lines without the quotes the
// update writes; the same value must not count as a change, or every save of
// the panel's settings costs an HAProxy reload at the next update.
func TestARuntimeVarsLineWithTheSameValueIsTheSame(t *testing.T) {
	for _, c := range []struct {
		existing, want string
		same           bool
	}{
		{`haproxy_socket: /run/haproxy/admin.sock`, `haproxy_socket: "/run/haproxy/admin.sock"`, true},
		{`haproxy_socket_group: 'hadmin'`, `haproxy_socket_group: "hadmin"`, true},
		{`haproxy_nbthread: 2`, `haproxy_nbthread: 2`, true},
		{`haproxy_socket: /run/other.sock`, `haproxy_socket: "/run/haproxy/admin.sock"`, false},
		{`haproxy_nbthread: "2"`, `haproxy_nbthread: 2`, false},
		{`haproxy_socket_group: hadmin`, `haproxy_socket: "hadmin"`, false},
		{`haproxy_socket: [a]`, `haproxy_socket: "a"`, false},
		{`haproxy_socket: : bad`, `haproxy_socket: "a"`, false},
	} {
		if got := sameYAMLLine(c.existing, c.want); got != c.same {
			t.Errorf("%q vs %q: %v", c.existing, c.want, got)
		}
	}
}
