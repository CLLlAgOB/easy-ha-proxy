package geoip

import "testing"

func TestMMDBValueBounds(t *testing.T) {
	reader := &Reader{data: []byte{0x43, 'D', 'E', 'U'}}
	value, next, err := reader.decodeValue(0, 0)
	if err != nil || value != "DEU" || next != 4 {
		t.Fatalf("valid string: %v, %d, %v", value, next, err)
	}
	reader.data = reader.data[:3]
	if _, _, err := reader.decodeValue(0, 0); err == nil {
		t.Fatal("truncated string must report an error")
	}
}
