package stages

import "testing"

// to_nice_json as Python writes it (the expected text came from json.dumps
// with Ansible's arguments): key order, nesting, escapes, numbers.
func TestPyNiceJSONMatchesPython(t *testing.T) {
	var v any
	if err := decodeJSON([]byte("{\"b\": 1, \"a\": [true, null, \"\\u00fc\\ud83d\\ude00\"], \"c\": {}, \"d\": 1.5, \"e\": 1e16, \"f\": 0.0001, \"g\": 1e-05, \"h\": 3.0, \"i\": [], \"j\": {\"z\": \"q\\\"\\\\/\\n\"}, \"k\": -2, \"l\": 123456789012.5}"), &v); err != nil {
		t.Fatal(err)
	}
	want := "{\n    \"a\": [\n        true,\n        null,\n        \"\\u00fc\\ud83d\\ude00\"\n    ],\n    \"b\": 1,\n    \"c\": {},\n    \"d\": 1.5,\n    \"e\": 1e+16,\n    \"f\": 0.0001,\n    \"g\": 1e-05,\n    \"h\": 3.0,\n    \"i\": [],\n    \"j\": {\n        \"z\": \"q\\\"\\\\/\\n\"\n    },\n    \"k\": -2,\n    \"l\": 123456789012.5\n}"
	if got := pyNiceJSON(v, 0); got != want {
		t.Fatalf("got:\n%s\nwant:\n%s", got, want)
	}
}
