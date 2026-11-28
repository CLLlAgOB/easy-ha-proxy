package vars

import "testing"

// Ansible's _escape_backslashes: only string literals inside {{ }} have
// their backslashes doubled.
func TestEscapeBackslashesFollowsAnsible(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{`{{ 'a\nb' }}`, `{{ 'a\\nb' }}`},
		{`plain \n text`, `plain \n text`},
		{`x\y {{ v }}`, `x\y {{ v }}`},
		{`{% raw %}{{ '\n' }}{% endraw %}{{ '\t' }}`, `{% raw %}{{ '\n' }}{% endraw %}{{ '\\t' }}`},
		{`{% set y = '\n' %}{{ y }}`, `{% set y = '\n' %}{{ y }}`},
		{`{# '\n' #}{{ "\d" }}`, `{# '\n' #}{{ "\\d" }}`},
		{`{{ x | default('^a\\.b') }}`, `{{ x | default('^a\\\\.b') }}`},
		{`{{ '}}' ~ '\n' }}`, `{{ '}}' ~ '\\n' }}`},
	} {
		if got := escapeBackslashes(c.in); got != c.want {
			t.Errorf("%s: got %s, want %s", c.in, got, c.want)
		}
	}
}

// A templated string reads a backslash in {{ }} literally, as Ansible
// does; template files (RenderFile) do not get this.
func TestTemplatedStringsKeepBackslashesInExpressions(t *testing.T) {
	s := &Set{cache: map[string]any{}, resolving: map[string]bool{}}
	s.env = newEnv(s.resolve)
	out, err := s.Render(`{{ 'a\nb' }}`)
	if err != nil {
		t.Fatal(err)
	}
	if out != `a\nb` {
		t.Fatalf("got %q", out)
	}
}
