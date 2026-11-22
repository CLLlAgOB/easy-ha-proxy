package controld

import (
	"bytes"
	"io"
	"os"
	"strings"
)

func isIPCharLeft(b byte) bool {
	return (b >= '0' && b <= '9') || (b >= 'a' && b <= 'f') || (b >= 'A' && b <= 'F') || b == '.' || b == ':'
}

func isIPCharRight(b byte) bool {
	return (b >= '0' && b <= '9') || (b >= 'a' && b <= 'f') || (b >= 'A' && b <= 'F')
}

// LineHasIP returns true when ip appears as a standalone address token in line,
// preventing prefix false positives such as 203.0.113.1 matching 203.0.113.10.
func LineHasIP(line, ip string) bool {
	if ip == "" || len(line) < len(ip) {
		return false
	}
	start := 0
	for {
		idx := strings.Index(line[start:], ip)
		if idx < 0 {
			return false
		}
		pos := start + idx
		leftOK := pos == 0 || !isIPCharLeft(line[pos-1])
		end := pos + len(ip)
		rightOK := end == len(line) || !isIPCharRight(line[end])
		if leftOK && rightOK {
			return true
		}
		start = pos + 1
	}
}

// GrepLastLogsForIP scans logPath backwards in fixed chunks (capped at maxBytes)
// and returns up to limit matching lines in chronological order.
func GrepLastLogsForIP(logPath, ip string, limit, chunkSize int, maxBytes int64) ([]string, error) {
	if limit <= 0 {
		limit = 30
	}
	if chunkSize <= 0 {
		chunkSize = 65536
	}
	f, err := os.Open(logPath)
	if err != nil {
		if os.IsNotExist(err) {
			return []string{}, nil
		}
		return nil, err
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	pos := info.Size()
	if pos == 0 {
		return []string{}, nil
	}

	var matches []string
	var carry []byte
	var scanned int64
	buf := make([]byte, chunkSize)

	for pos > 0 && len(matches) < limit {
		if maxBytes > 0 && scanned >= maxBytes {
			break
		}
		readSize := int64(chunkSize)
		if readSize > pos {
			readSize = pos
		}
		if maxBytes > 0 && scanned+readSize > maxBytes {
			readSize = maxBytes - scanned
		}
		pos -= readSize
		scanned += readSize

		n, err := f.ReadAt(buf[:readSize], pos)
		if err != nil && err != io.EOF {
			return nil, err
		}
		chunk := make([]byte, n+len(carry))
		copy(chunk, buf[:n])
		copy(chunk[n:], carry)

		lines := bytes.Split(chunk, []byte{'\n'})
		if pos > 0 {
			carry = append([]byte(nil), lines[0]...)
			lines = lines[1:]
		} else {
			carry = nil
		}

		for i := len(lines) - 1; i >= 0 && len(matches) < limit; i-- {
			line := strings.TrimRight(string(lines[i]), "\r")
			if line == "" {
				continue
			}
			if LineHasIP(line, ip) {
				matches = append(matches, line)
			}
		}
	}

	// Reverse back into chronological (ascending) order.
	for i, j := 0, len(matches)-1; i < j; i, j = i+1, j-1 {
		matches[i], matches[j] = matches[j], matches[i]
	}
	return matches, nil
}
