package controld

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode"
	"unicode/utf8"
)

func itoa(n int) string { return strconv.Itoa(n) }

// pySpace is str.isspace() for one rune.
func pySpace(r rune) bool {
	switch r {
	case ' ', '\t', '\n', '\r', '\v', '\f', 0x1c, 0x1d, 0x1e, 0x1f, 0x85:
		return true
	}
	return unicode.IsSpace(r)
}

func pyStrip(s string) string { return strings.TrimFunc(s, pySpace) }

func pyFields(s string) []string { return strings.FieldsFunc(s, pySpace) }

// pySplitlines is str.splitlines().
func pySplitlines(s string) []string {
	out := []string{}
	start := 0
	runes := []rune(s)
	for i := 0; i < len(runes); i++ {
		r := runes[i]
		switch r {
		case '\n', '\r', '\v', '\f', 0x1c, 0x1d, 0x1e, 0x85, 0x2028, 0x2029:
			out = append(out, string(runes[start:i]))
			if r == '\r' && i+1 < len(runes) && runes[i+1] == '\n' {
				i++
			}
			start = i + 1
		}
	}
	if start < len(runes) {
		out = append(out, string(runes[start:]))
	}
	return out
}

// universalNewlines is what text=True does to a child's output.
func universalNewlines(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "\r\n", "\n"), "\r", "\n")
}

// utf8Check is bytes.decode("utf-8") raising UnicodeDecodeError.
func utf8Check(raw []byte) error {
	for i := 0; i < len(raw); {
		r, size := utf8.DecodeRune(raw[i:])
		if r == utf8.RuneError && size <= 1 {
			reason := "invalid start byte"
			c := raw[i]
			if c >= 0xc2 && c <= 0xf4 {
				need := 1
				if c >= 0xe0 {
					need = 2
				}
				if c >= 0xf0 {
					need = 3
				}
				if i+need >= len(raw)+0 && func() bool {
					for j := i + 1; j < len(raw); j++ {
						if raw[j]&0xc0 != 0x80 {
							return false
						}
					}
					return true
				}() {
					return vErr("'utf-8' codec can't decode byte 0x%02x in position %d: unexpected end of data", c, i)
				}
				reason = "invalid continuation byte"
			}
			return vErr("'utf-8' codec can't decode byte 0x%02x in position %d: %s", c, i, reason)
		}
		i += size
	}
	return nil
}

func sha256Hex(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func compareDigest(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func tokenHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func tokenURLSafe(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func b64(raw []byte) string { return base64.StdEncoding.EncodeToString(raw) }

// compactStamp is strftime('%Y%m%dT%H%M%S%fZ') in UTC.
func compactStamp(t time.Time) string {
	t = t.UTC()
	return t.Format("20060102T150405") + fmt.Sprintf("%06dZ", t.Nanosecond()/1000)
}

func isHex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func isCountryCode(s string) bool {
	return len(s) == 2 && s[0] >= 'A' && s[0] <= 'Z' && s[1] >= 'A' && s[1] <= 'Z'
}

// pyOSErrorClass names the OSError subclass Python raises for errno.
func pyOSErrorClass(errno syscall.Errno) string {
	switch errno {
	case syscall.ENOENT:
		return "FileNotFoundError"
	case syscall.EACCES, syscall.EPERM:
		return "PermissionError"
	case syscall.EEXIST:
		return "FileExistsError"
	case syscall.ENOTDIR:
		return "NotADirectoryError"
	case syscall.EISDIR:
		return "IsADirectoryError"
	case syscall.ECONNREFUSED:
		return "ConnectionRefusedError"
	}
	return "OSError"
}

// pyReprErr is repr(exc) for the errors a reply quotes with !r.
func pyReprErr(err error) string {
	var pe *os.PathError
	if errors.As(err, &pe) {
		var errno syscall.Errno
		if errors.As(pe.Err, &errno) {
			msg := errno.Error()
			if msg != "" {
				msg = strings.ToUpper(msg[:1]) + msg[1:]
			}
			return fmt.Sprintf("%s(%d, %s)", pyOSErrorClass(errno), int(errno), pyRepr(msg))
		}
	}
	var te *timeoutErr
	if errors.As(err, &te) {
		return fmt.Sprintf("TimeoutExpired(%s, %s)", pyArgv(te.argv), pyNum(te.seconds))
	}
	var ve *valueError
	if errors.As(err, &ve) {
		return "ValueError(" + pyRepr(ve.msg) + ")"
	}
	var re *runtimeError
	if errors.As(err, &re) {
		return "RuntimeError(" + pyRepr(re.msg) + ")"
	}
	return "Exception(" + pyRepr(err.Error()) + ")"
}

// pyNetErr is str(exc) for socket errors.
func pyNetErr(err error) string {
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return "timed out"
	}
	var errno syscall.Errno
	if errors.As(err, &errno) {
		msg := errno.Error()
		if msg != "" {
			msg = strings.ToUpper(msg[:1]) + msg[1:]
		}
		return fmt.Sprintf("[Errno %d] %s", int(errno), msg)
	}
	return err.Error()
}

// isExecMissing reports a child that could not start at all.
func isExecMissing(err error) bool {
	var ee *exec.Error
	if errors.As(err, &ee) {
		return true
	}
	var pe *os.PathError
	return errors.As(err, &pe)
}

func isRuntime(err error) bool {
	var re *runtimeError
	return errors.As(err, &re)
}

func isValue(err error) bool {
	var ve *valueError
	return errors.As(err, &ve)
}

func isNotExist(err error) bool {
	return errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ENOENT)
}
