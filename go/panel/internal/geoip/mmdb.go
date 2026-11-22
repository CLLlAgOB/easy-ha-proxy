// Package geoip implements a zero-dependency MaxMind DB (.mmdb) reader with
// mtime-based hot reload for country lookups in /api/country-batch.
package geoip

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net/netip"
	"os"
	"sync"
	"time"
)

var metadataMarker = []byte("\xab\xcd\xefMaxMind.com")

// Reader caches an in-memory .mmdb file and reloads it atomically if mtime changes.
type Reader struct {
	path string

	mu         sync.RWMutex
	mtime      time.Time
	data       []byte
	nodeCount  uint32
	recordSize uint16
	ipVersion  uint16
	treeSize   uint64
	dataStart  uint64
}

// NewReader creates a lazy-loading Reader for the given .mmdb path.
func NewReader(path string) *Reader {
	return &Reader{path: path}
}

// CountryCode returns the two-letter ISO country code for ipStr, or "" if
// unavailable or not found.
func (r *Reader) CountryCode(ipStr string) string {
	addr, err := netip.ParseAddr(ipStr)
	if err != nil {
		return ""
	}
	if err := r.ensureLoaded(); err != nil {
		return ""
	}

	r.mu.RLock()
	defer r.mu.RUnlock()
	if len(r.data) == 0 || r.nodeCount == 0 {
		return ""
	}

	var ipBytes []byte
	startNode := uint32(0)
	if addr.Is4() {
		a4 := addr.As4()
		if r.ipVersion == 6 {
			// Walk IPv4-mapped prefix (96 zero bits) from root.
			node, ok := r.walkZeros(96)
			if !ok {
				return ""
			}
			startNode = node
		}
		ipBytes = a4[:]
	} else {
		if r.ipVersion != 6 {
			return ""
		}
		a16 := addr.As16()
		ipBytes = a16[:]
	}

	node := startNode
	for _, b := range ipBytes {
		for bit := 7; bit >= 0; bit-- {
			if node >= r.nodeCount {
				break
			}
			right := (b >> uint(bit)) & 1
			node = r.readNode(node, right)
		}
		if node >= r.nodeCount {
			break
		}
	}

	if node == r.nodeCount {
		return ""
	}
	if node < r.nodeCount {
		return ""
	}
	offset := uint64(node-r.nodeCount) - 16
	dataOffset := r.dataStart + offset
	if dataOffset >= uint64(len(r.data)) {
		return ""
	}
	val, _, err := r.decodeValue(dataOffset, 0)
	if err != nil {
		return ""
	}
	return extractCountryCode(val)
}

func (r *Reader) walkZeros(bits int) (uint32, bool) {
	node := uint32(0)
	for i := 0; i < bits; i++ {
		if node >= r.nodeCount {
			return 0, false
		}
		node = r.readNode(node, 0)
	}
	return node, true
}

func (r *Reader) ensureLoaded() error {
	if r.path == "" {
		return errors.New("geoip db path not configured")
	}
	info, err := os.Stat(r.path)
	if err != nil {
		return err
	}

	r.mu.RLock()
	upToDate := len(r.data) > 0 && info.ModTime().Equal(r.mtime)
	r.mu.RUnlock()
	if upToDate {
		return nil
	}

	raw, err := os.ReadFile(r.path)
	if err != nil {
		return err
	}
	idx := bytes.LastIndex(raw, metadataMarker)
	if idx < 0 {
		return errors.New("invalid mmdb: missing metadata marker")
	}

	tmp := &Reader{data: raw, dataStart: uint64(idx + len(metadataMarker))}
	metaVal, _, err := tmp.decodeValue(tmp.dataStart, 0)
	if err != nil {
		return err
	}
	meta, ok := metaVal.(map[string]any)
	if !ok {
		return errors.New("invalid mmdb metadata")
	}

	nodeCount := uint32(toUint64(meta["node_count"]))
	recordSize := uint16(toUint64(meta["record_size"]))
	ipVersion := uint16(toUint64(meta["ip_version"]))
	if nodeCount == 0 || (recordSize != 24 && recordSize != 28 && recordSize != 32) {
		return errors.New("unsupported mmdb geometry")
	}
	treeSize := (uint64(recordSize) * 2 / 8) * uint64(nodeCount)
	dataStart := treeSize + 16
	if dataStart >= uint64(len(raw)) {
		return errors.New("corrupt mmdb section layout")
	}

	r.mu.Lock()
	r.mtime = info.ModTime()
	r.data = raw
	r.nodeCount = nodeCount
	r.recordSize = recordSize
	r.ipVersion = ipVersion
	r.treeSize = treeSize
	r.dataStart = dataStart
	r.mu.Unlock()
	return nil
}

func (r *Reader) readNode(node uint32, right uint8) uint32 {
	nodeBytes := uint64(r.recordSize) * 2 / 8
	base := uint64(node) * nodeBytes
	switch r.recordSize {
	case 24:
		off := base
		if right == 1 {
			off += 3
		}
		return uint32(r.data[off])<<16 | uint32(r.data[off+1])<<8 | uint32(r.data[off+2])
	case 28:
		mid := r.data[base+3]
		if right == 0 {
			return uint32(mid>>4)<<24 | uint32(r.data[base])<<16 | uint32(r.data[base+1])<<8 | uint32(r.data[base+2])
		}
		return uint32(mid&0x0f)<<24 | uint32(r.data[base+4])<<16 | uint32(r.data[base+5])<<8 | uint32(r.data[base+6])
	case 32:
		off := base
		if right == 1 {
			off += 4
		}
		return binary.BigEndian.Uint32(r.data[off : off+4])
	default:
		return 0
	}
}

func (r *Reader) decodeValue(offset uint64, depth int) (any, uint64, error) {
	if depth > 32 || offset >= uint64(len(r.data)) {
		return nil, offset, errors.New("mmdb decode bounds exceeded")
	}
	ctrl := r.data[offset]
	offset++
	typ := ctrl >> 5
	size := uint64(ctrl & 0x1f)

	if typ == 1 { // pointer
		ptrSize := ((ctrl >> 3) & 0x03)
		var ptr uint64
		switch ptrSize {
		case 0:
			if offset >= uint64(len(r.data)) {
				return nil, offset, errors.New("truncated pointer")
			}
			ptr = uint64(ctrl&0x07)<<8 | uint64(r.data[offset])
			offset++
		case 1:
			if offset+2 > uint64(len(r.data)) {
				return nil, offset, errors.New("truncated pointer")
			}
			ptr = (uint64(ctrl&0x07)<<16 | uint64(r.data[offset])<<8 | uint64(r.data[offset+1])) + 2048
			offset += 2
		case 2:
			if offset+3 > uint64(len(r.data)) {
				return nil, offset, errors.New("truncated pointer")
			}
			ptr = (uint64(ctrl&0x07)<<24 | uint64(r.data[offset])<<16 | uint64(r.data[offset+1])<<8 | uint64(r.data[offset+2])) + 526336
			offset += 3
		case 3:
			if offset+4 > uint64(len(r.data)) {
				return nil, offset, errors.New("truncated pointer")
			}
			ptr = uint64(binary.BigEndian.Uint32(r.data[offset : offset+4]))
			offset += 4
		}
		v, _, err := r.decodeValue(r.dataStart+ptr, depth+1)
		return v, offset, err
	}

	if typ == 0 { // extended type
		if offset >= uint64(len(r.data)) {
			return nil, offset, errors.New("truncated extended type")
		}
		typ = r.data[offset] + 7
		offset++
	}

	switch size {
	case 29:
		if offset >= uint64(len(r.data)) {
			return nil, offset, errors.New("truncated size")
		}
		size = 29 + uint64(r.data[offset])
		offset++
	case 30:
		if offset+2 > uint64(len(r.data)) {
			return nil, offset, errors.New("truncated size")
		}
		size = 285 + uint64(binary.BigEndian.Uint16(r.data[offset:offset+2]))
		offset += 2
	case 31:
		if offset+3 > uint64(len(r.data)) {
			return nil, offset, errors.New("truncated size")
		}
		size = 65821 + (uint64(r.data[offset])<<16 | uint64(r.data[offset+1])<<8 | uint64(r.data[offset+2]))
		offset += 3
	}

	switch typ {
	case 2: // utf8 string
		if offset+size > uint64(len(r.data)) {
			return nil, offset, errors.New("truncated string")
		}
		return string(r.data[offset : offset+size]), offset + size, nil
	case 5, 6, 9, 10: // uint16, uint32, uint64, uint128
		if offset+size > uint64(len(r.data)) {
			return nil, offset, errors.New("truncated uint")
		}
		var n uint64
		for i := uint64(0); i < size && i < 8; i++ {
			n = (n << 8) | uint64(r.data[offset+i])
		}
		return n, offset + size, nil
	case 7: // map
		m := make(map[string]any, size)
		for i := uint64(0); i < size; i++ {
			k, nextOff, err := r.decodeValue(offset, depth+1)
			if err != nil {
				return nil, nextOff, err
			}
			v, nextOff, err := r.decodeValue(nextOff, depth+1)
			if err != nil {
				return nil, nextOff, err
			}
			if ks, ok := k.(string); ok {
				m[ks] = v
			}
			offset = nextOff
		}
		return m, offset, nil
	case 11: // array
		arr := make([]any, 0, size)
		for i := uint64(0); i < size; i++ {
			v, nextOff, err := r.decodeValue(offset, depth+1)
			if err != nil {
				return nil, nextOff, err
			}
			arr = append(arr, v)
			offset = nextOff
		}
		return arr, offset, nil
	case 14: // bool
		return size != 0, offset, nil
	default:
		if offset+size > uint64(len(r.data)) {
			return nil, offset, errors.New("truncated scalar")
		}
		return nil, offset + size, nil
	}
}

func extractCountryCode(val any) string {
	m, ok := val.(map[string]any)
	if !ok {
		return ""
	}
	if c, ok := m["country"].(map[string]any); ok {
		if iso, ok := c["iso_code"].(string); ok && len(iso) == 2 {
			return iso
		}
	}
	if rc, ok := m["registered_country"].(map[string]any); ok {
		if iso, ok := rc["iso_code"].(string); ok && len(iso) == 2 {
			return iso
		}
	}
	return ""
}

func toUint64(v any) uint64 {
	if u, ok := v.(uint64); ok {
		return u
	}
	return 0
}
