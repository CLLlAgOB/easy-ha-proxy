package pyx

import (
	"math"
	"testing"
)

func TestDecodeRejectsTrailingClosingTokens(t *testing.T) {
	for _, raw := range []string{`{"a":1}}`, `[1,2]]`, `{"a":1} {"b":2}`, `123 junk`} {
		if _, err := Decode([]byte(raw)); err == nil {
			t.Fatalf("expected error for trailing data in %q", raw)
		}
	}
	v, err := Decode([]byte("{\"a\": 1} \n\t"))
	if err != nil || Map(v) == nil {
		t.Fatalf("expected valid JSON object, got v=%v err=%v", v, err)
	}
}

func TestStrOrHandlesNonFiniteAndLargeFloats(t *testing.T) {
	if got := StrOr(math.Inf(1)); got != "+Inf" {
		t.Fatalf("StrOr(+Inf) = %q, want +Inf", got)
	}
	if got := StrOr(math.NaN()); got != "NaN" {
		t.Fatalf("StrOr(NaN) = %q, want NaN", got)
	}
	if got := StrOr(1e20); got == "-9223372036854775808" {
		t.Fatalf("StrOr(1e20) overflowed int64: %q", got)
	}
	if got := StrOr(42.0); got != "42" {
		t.Fatalf("StrOr(42.0) = %q, want 42", got)
	}
}
