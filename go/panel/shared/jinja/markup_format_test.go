package jinja

import "testing"

func TestMarkupReprEscapesArgument(t *testing.T) {
	got, err := percentFormat(Markup("%r"), "%r", "A&B")
	if err != nil || got != Markup("&#39;A&amp;B&#39;") {
		t.Fatalf("formatted repr: %v, %v", got, err)
	}
}
