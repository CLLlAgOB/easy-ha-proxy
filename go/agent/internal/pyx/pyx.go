// Package pyx holds the small pieces of Python semantics the ported daemons
// need so their files and replies stay byte-compatible with the Python
// implementations they replace: str()/bool()/int() of decoded JSON values,
// datetime.isoformat(), json.dumps(sort_keys=True, ensure_ascii=False).
package pyx

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// ISO is datetime.isoformat() for an aware datetime in t's zone.
func ISO(t time.Time) string {
	_, offset := t.Zone()
	sign := "+"
	if offset < 0 {
		sign = "-"
		offset = -offset
	}
	zone := fmt.Sprintf("%s%02d:%02d", sign, offset/3600, (offset%3600)/60)
	if t.Nanosecond()/1000 == 0 {
		return t.Format("2006-01-02T15:04:05") + zone
	}
	return t.Format("2006-01-02T15:04:05.000000") + zone
}

// UTCNow is datetime.now(timezone.utc).isoformat().
func UTCNow() string { return ISO(time.Now().UTC()) }

// FromTimestamp is datetime.fromtimestamp(ts, tz).
func FromTimestamp(ts float64, loc *time.Location) time.Time {
	sec, frac := math.Modf(ts)
	return time.Unix(int64(sec), int64(math.Round(frac*1e6))*1000).In(loc)
}

// Timestamp is datetime.timestamp().
func Timestamp(t time.Time) float64 {
	return float64(t.Unix()) + float64(t.Nanosecond()/1000)/1e6
}

// ParseISO is datetime.fromisoformat; aware reports whether a zone was given.
func ParseISO(raw string) (t time.Time, aware bool, ok bool) {
	raw = strings.TrimSpace(raw)
	if strings.HasSuffix(raw, "Z") {
		raw = raw[:len(raw)-1] + "+00:00"
	}
	for _, layout := range []string{
		"2006-01-02T15:04:05.999999999-07:00", "2006-01-02T15:04:05-07:00", "2006-01-02T15:04-07:00",
		"2006-01-02 15:04:05.999999999-07:00", "2006-01-02 15:04:05-07:00",
	} {
		if v, err := time.Parse(layout, raw); err == nil {
			return v, true, true
		}
	}
	for _, layout := range []string{
		"2006-01-02T15:04:05.999999999", "2006-01-02T15:04:05", "2006-01-02T15:04",
		"2006-01-02 15:04:05.999999999", "2006-01-02 15:04:05", "2006-01-02",
	} {
		if v, err := time.ParseInLocation(layout, raw, time.Local); err == nil {
			return v, false, true
		}
	}
	return time.Time{}, false, false
}

// Str is str(value) for decoded JSON, with None -> "None".
func Str(v any) string {
	switch x := v.(type) {
	case nil:
		return "None"
	case string:
		return x
	case json.Number:
		return x.String()
	case bool:
		if x {
			return "True"
		}
		return "False"
	case float64:
		if x == math.Trunc(x) && math.Abs(x) < 1e16 {
			return strconv.FormatInt(int64(x), 10) + ".0"
		}
		return strconv.FormatFloat(x, 'g', -1, 64)
	case int:
		return strconv.Itoa(x)
	case int64:
		return strconv.FormatInt(x, 10)
	}
	b, _ := json.Marshal(v)
	return string(b)
}

// StrOr is str(value or "").
func StrOr(v any) string {
	if !Truthy(v) {
		return ""
	}
	if f, ok := v.(float64); ok && f == math.Trunc(f) {
		return strconv.FormatInt(int64(f), 10)
	}
	return Str(v)
}

// Truthy is bool(value).
func Truthy(v any) bool {
	switch x := v.(type) {
	case nil:
		return false
	case bool:
		return x
	case string:
		return x != ""
	case float64:
		return x != 0
	case int:
		return x != 0
	case int64:
		return x != 0
	case json.Number:
		f, _ := x.Float64()
		return f != 0
	case []any:
		return len(x) > 0
	case []string:
		return len(x) > 0
	case map[string]any:
		return len(x) > 0
	}
	return true
}

// Int reports v as a Python int: type(v) is int (JSON integers only).
func Int(v any) (int64, bool) {
	switch x := v.(type) {
	case int:
		return int64(x), true
	case int64:
		return x, true
	case json.Number:
		n, err := x.Int64()
		return n, err == nil
	case float64:
		// Values decoded without UseNumber: a whole number is what was sent.
		if x == math.Trunc(x) && !math.IsInf(x, 0) {
			return int64(x), true
		}
	}
	return 0, false
}

// Number reports v as int or float (type(v) in (int, float)), not bool.
func Number(v any) (float64, bool) {
	switch x := v.(type) {
	case int:
		return float64(x), true
	case int64:
		return float64(x), true
	case float64:
		return x, true
	case json.Number:
		f, err := x.Float64()
		return f, err == nil
	}
	return 0, false
}

// Float is float(value or 0) where unparseable values are 0.
func Float(v any) float64 {
	if f, ok := Number(v); ok {
		return f
	}
	if s, ok := v.(string); ok {
		f, _ := strconv.ParseFloat(strings.TrimSpace(s), 64)
		return f
	}
	if b, ok := v.(bool); ok && b {
		return 1
	}
	return 0
}

// TruncRunes is s[:n] by code points.
func TruncRunes(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	return string([]rune(s)[:n])
}

// RandomHex returns n random bytes as hex.
func RandomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// UUIDHex is uuid.uuid4().hex.
func UUIDHex() string { return RandomHex(16) }

// Encode is json.dumps(payload, ensure_ascii=False, sort_keys=True) + "\n".
func Encode(payload any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(payload); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Compact is json.dumps(material, sort_keys=True, separators=(",", ":")),
// ensure_ascii as asked.
func Compact(payload any, ensureASCII bool) []byte {
	raw, _ := Encode(payload)
	raw = bytes.TrimRight(raw, "\n")
	if !ensureASCII {
		return pythonEscapes(raw, false)
	}
	return pythonEscapes(raw, true)
}

// pythonEscapes rewrites Go's JSON string escapes into Python's: Go writes
// <-style escapes only with SetEscapeHTML, so the differences left are
// non-ASCII (escaped by Python when ensure_ascii) and  / .
func pythonEscapes(raw []byte, ensureASCII bool) []byte {
	var out bytes.Buffer
	inString := false
	for i := 0; i < len(raw); {
		c := raw[i]
		if c == '"' {
			inString = !inString
			out.WriteByte(c)
			i++
			continue
		}
		if inString && c == '\\' && i+1 < len(raw) {
			if raw[i+1] == 'u' && i+5 < len(raw) {
				code := string(raw[i+2 : i+6])
				if !ensureASCII && (code == "2028" || code == "2029") {
					n, _ := strconv.ParseUint(code, 16, 32)
					out.WriteRune(rune(n))
					i += 6
					continue
				}
			}
			out.Write(raw[i : i+2])
			i += 2
			continue
		}
		if inString && ensureASCII && c >= 0x80 {
			r, size := utf8.DecodeRune(raw[i:])
			if r > 0xFFFF {
				r -= 0x10000
				fmt.Fprintf(&out, `\u%04x\u%04x`, 0xD800+(r>>10), 0xDC00+(r&0x3FF))
			} else {
				fmt.Fprintf(&out, `\u%04x`, r)
			}
			i += size
			continue
		}
		out.WriteByte(c)
		i++
	}
	return out.Bytes()
}

// Decode parses JSON keeping numbers as json.Number.
func Decode(raw []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	if dec.More() {
		return nil, fmt.Errorf("Extra data")
	}
	return v, nil
}

// Map returns v as a JSON object or nil.
func Map(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}

// List returns v as a JSON array or nil.
func List(v any) []any {
	l, _ := v.([]any)
	return l
}

// Get is dict.get(key, default).
func Get(m map[string]any, key string, def any) any {
	if v, ok := m[key]; ok {
		return v
	}
	return def
}

// Copy is dict(m).
func Copy(m map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}
