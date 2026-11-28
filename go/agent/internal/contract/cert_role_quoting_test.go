package contract

import "testing"

func TestTheSanFlagsQuoteEachName(t *testing.T) {
	template := read(t, "ansible/roles/cert/templates/_san_flags.j2")
	mustContain(t, template, "map('quote')", "_san_flags.j2")
}
