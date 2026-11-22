package tools

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	GeoIPDBName         = "dbip-country-lite.mmdb"
	GeoIPAllowedName    = "allowed.geo"
	GeoIPStateName      = "state.json"
	GeoIPFormatVersion  = 1
	GeoIPMaxCompressed  = 64 * 1024 * 1024
	GeoIPMaxDBBytes     = 128 * 1024 * 1024
	GeoIPMaxSelection   = 16 * 1024
)

var (
	isoCountryRe = regexp.MustCompile(`^[A-Z]{2}$`)
	mmdbMarker   = []byte("\xab\xcd\xefMaxMind.com")
)

// GeoIPSelection mirrors /etc/haproxy/geoip/selection.json.
type GeoIPSelection struct {
	Version             int      `json:"version"`
	Countries           []string `json:"countries"`
	AccessFilterEnabled bool     `json:"access_filter_enabled"`
}

// NormalizeCountries validates and returns sorted unique ISO-3166-1 alpha-2 country codes.
func NormalizeCountries(values []string) ([]string, error) {
	seen := make(map[string]struct{})
	for _, raw := range values {
		for _, part := range strings.Split(raw, ",") {
			code := strings.ToUpper(strings.TrimSpace(part))
			if code == "" {
				continue
			}
			if !isoCountryRe.MatchString(code) {
				return nil, fmt.Errorf("invalid ISO country code: %q", part)
			}
			seen[code] = struct{}{}
		}
	}
	out := make([]string, 0, len(seen))
	for c := range seen {
		out = append(out, c)
	}
	sort.Strings(out)
	return out, nil
}

// LoadGeoIPSelection reads selection.json safely without following symlinks.
func LoadGeoIPSelection(path string) (GeoIPSelection, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return GeoIPSelection{}, fmt.Errorf("GeoIP selection file is missing: %s", path)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return GeoIPSelection{}, errors.New("GeoIP selection must be a regular file")
	}
	if info.Size() <= 0 || info.Size() > GeoIPMaxSelection {
		return GeoIPSelection{}, errors.New("GeoIP selection has an invalid size")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return GeoIPSelection{}, err
	}
	var sel GeoIPSelection
	if err := json.Unmarshal(raw, &sel); err != nil {
		return GeoIPSelection{}, fmt.Errorf("cannot read GeoIP selection: %w", err)
	}
	if sel.Version != 1 {
		return GeoIPSelection{}, errors.New("unsupported GeoIP selection version")
	}
	norm, err := NormalizeCountries(sel.Countries)
	if err != nil {
		return GeoIPSelection{}, err
	}
	sel.Countries = norm
	return sel, nil
}

// SaveGeoIPSelection writes selection.json atomically with mode 0644.
func SaveGeoIPSelection(path string, countries []string, accessFilter bool) (GeoIPSelection, error) {
	norm, err := NormalizeCountries(countries)
	if err != nil {
		return GeoIPSelection{}, err
	}
	sel := GeoIPSelection{
		Version:             1,
		Countries:           norm,
		AccessFilterEnabled: accessFilter,
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return GeoIPSelection{}, err
	}
	raw, err := json.MarshalIndent(sel, "", "  ")
	if err != nil {
		return GeoIPSelection{}, err
	}
	if err := writeFileAtomic(path, append(raw, '\n'), 0o644); err != nil {
		return GeoIPSelection{}, err
	}
	return sel, nil
}

// --- Zero-dependency MaxMind DB (.mmdb) binary tree reader -----------------

type mmdbReader struct {
	data       []byte
	nodeCount  uint32
	recordSize uint32
	ipVersion  uint16
	treeSize   int
	dataOffset int
	buildEpoch uint64
}

func openMMDB(raw []byte) (*mmdbReader, error) {
	idx := bytes.LastIndex(raw, mmdbMarker)
	if idx < 0 {
		return nil, errors.New("invalid MMDB: metadata marker not found")
	}
	metaOff := idx + len(mmdbMarker)
	r := &mmdbReader{data: raw}
	val, _, err := r.decodeValue(metaOff, metaOff)
	if err != nil {
		return nil, fmt.Errorf("invalid MMDB metadata: %w", err)
	}
	meta, ok := val.(map[string]any)
	if !ok {
		return nil, errors.New("invalid MMDB metadata map")
	}
	r.nodeCount = uint32(mmdbUint(meta["node_count"]))
	r.recordSize = uint32(mmdbUint(meta["record_size"]))
	r.ipVersion = uint16(mmdbUint(meta["ip_version"]))
	r.buildEpoch = mmdbUint(meta["build_epoch"])
	if r.nodeCount == 0 || (r.recordSize != 24 && r.recordSize != 28 && r.recordSize != 32) {
		return nil, fmt.Errorf("unsupported MMDB geometry: nodes=%d record_size=%d", r.nodeCount, r.recordSize)
	}
	r.treeSize = int(r.nodeCount) * int(r.recordSize/4)
	r.dataOffset = r.treeSize + 16
	if r.dataOffset > len(raw) {
		return nil, errors.New("truncated MMDB search tree")
	}
	return r, nil
}

func mmdbUint(v any) uint64 {
	switch n := v.(type) {
	case uint64:
		return n
	case int64:
		if n > 0 {
			return uint64(n)
		}
	}
	return 0
}

func (r *mmdbReader) readNode(node uint32, bit int) uint32 {
	nodeBytes := int(r.recordSize / 4)
	off := int(node) * nodeBytes
	switch r.recordSize {
	case 24:
		if bit == 0 {
			return uint32(r.data[off])<<16 | uint32(r.data[off+1])<<8 | uint32(r.data[off+2])
		}
		return uint32(r.data[off+3])<<16 | uint32(r.data[off+4])<<8 | uint32(r.data[off+5])
	case 28:
		mid := r.data[off+3]
		if bit == 0 {
			return uint32(mid>>4)<<24 | uint32(r.data[off])<<16 | uint32(r.data[off+1])<<8 | uint32(r.data[off+2])
		}
		return uint32(mid&0x0f)<<24 | uint32(r.data[off+4])<<16 | uint32(r.data[off+5])<<8 | uint32(r.data[off+6])
	case 32:
		if bit == 0 {
			return binary.BigEndian.Uint32(r.data[off : off+4])
		}
		return binary.BigEndian.Uint32(r.data[off+4 : off+8])
	}
	return 0
}

func (r *mmdbReader) decodeValue(off, base int) (any, int, error) {
	if off >= len(r.data) {
		return nil, off, errors.New("unexpected EOF in MMDB data")
	}
	ctrl := r.data[off]
	off++
	typ := ctrl >> 5
	if typ == 1 { // pointer
		ptrSize := (ctrl >> 3) & 0x03
		val := uint32(ctrl & 0x07)
		var ptr int
		switch ptrSize {
		case 0:
			ptr = int(val<<8 | uint32(r.data[off]))
			off++
		case 1:
			ptr = int(val<<16|uint32(r.data[off])<<8|uint32(r.data[off+1])) + 2048
			off += 2
		case 2:
			ptr = int(val<<24|uint32(r.data[off])<<16|uint32(r.data[off+1])<<8|uint32(r.data[off+2])) + 526336
			off += 3
		case 3:
			ptr = int(binary.BigEndian.Uint32(r.data[off : off+4]))
			off += 4
		}
		v, _, err := r.decodeValue(base+ptr, base)
		return v, off, err
	}
	if typ == 0 { // extended type
		typ = r.data[off] + 7
		off++
	}
	size := int(ctrl & 0x1f)
	switch size {
	case 29:
		size = 29 + int(r.data[off])
		off++
	case 30:
		size = 285 + int(binary.BigEndian.Uint16(r.data[off:off+2]))
		off += 2
	case 31:
		size = 65821 + int(uint32(r.data[off])<<16|uint32(r.data[off+1])<<8|uint32(r.data[off+2]))
		off += 3
	}

	switch typ {
	case 2: // UTF-8 string
		return string(r.data[off : off+size]), off + size, nil
	case 3: // double
		return nil, off + size, nil
	case 4: // bytes
		return r.data[off : off+size], off + size, nil
	case 5, 6, 9, 10: // uint16/32/64/128
		var u uint64
		for i := 0; i < size && i < 8; i++ {
			u = (u << 8) | uint64(r.data[off+i])
		}
		return u, off + size, nil
	case 7: // map
		m := make(map[string]any, size)
		for i := 0; i < size; i++ {
			k, nextOff, err := r.decodeValue(off, base)
			if err != nil {
				return nil, nextOff, err
			}
			v, nextOff2, err := r.decodeValue(nextOff, base)
			if err != nil {
				return nil, nextOff2, err
			}
			if ks, ok := k.(string); ok {
				m[ks] = v
			}
			off = nextOff2
		}
		return m, off, nil
	case 8: // int32
		var u uint64
		for i := 0; i < size; i++ {
			u = (u << 8) | uint64(r.data[off+i])
		}
		return int64(int32(u)), off + size, nil
	case 11: // array
		arr := make([]any, size)
		for i := 0; i < size; i++ {
			v, nextOff, err := r.decodeValue(off, base)
			if err != nil {
				return nil, nextOff, err
			}
			arr[i] = v
			off = nextOff
		}
		return arr, off, nil
	case 14: // boolean
		return size != 0, off, nil
	case 15: // float
		return nil, off + size, nil
	default:
		return nil, off + size, nil
	}
}

// ExtractCountryNetworks walks the MMDB search tree and extracts IPv4 CIDRs per ISO country code.
func ExtractCountryNetworks(mmdbBytes []byte) (map[string][]string, uint64, error) {
	r, err := openMMDB(mmdbBytes)
	if err != nil {
		return nil, 0, err
	}
	byCountry := make(map[string][]string)

	// Walk IPv4 subtree: for IPv6 databases, follow 96 zero bits (::/96) to reach the IPv4 subtree.
	startNode := uint32(0)
	if r.ipVersion == 6 {
		for i := 0; i < 96; i++ {
			next := r.readNode(startNode, 0)
			if next >= r.nodeCount {
				return byCountry, r.buildEpoch, nil
			}
			startNode = next
		}
	}

	var walk func(node uint32, ip uint32, depth int)
	walk = func(node uint32, ip uint32, depth int) {
		if depth > 32 {
			return
		}
		if node == r.nodeCount {
			return // empty
		}
		if node > r.nodeCount {
			dataPtr := int(node-r.nodeCount-16) + r.dataOffset
			val, _, err := r.decodeValue(dataPtr, r.dataOffset)
			if err != nil {
				return
			}
			code := extractISOCode(val)
			if isoCountryRe.MatchString(code) {
				var b [4]byte
				binary.BigEndian.PutUint32(b[:], ip)
				pfx := netip.PrefixFrom(netip.AddrFrom4(b), depth)
				byCountry[code] = append(byCountry[code], pfx.String())
			}
			return
		}
		if depth == 32 {
			return
		}
		walk(r.readNode(node, 0), ip, depth+1)
		walk(r.readNode(node, 1), ip|(uint32(1)<<uint(31-depth)), depth+1)
	}
	walk(startNode, 0, 0)
	return byCountry, r.buildEpoch, nil
}

func extractISOCode(val any) string {
	m, ok := val.(map[string]any)
	if !ok {
		return ""
	}
	if country, ok := m["country"].(map[string]any); ok {
		if code, ok := country["iso_code"].(string); ok {
			return strings.ToUpper(strings.TrimSpace(code))
		}
	}
	if code, ok := m["iso_code"].(string); ok {
		return strings.ToUpper(strings.TrimSpace(code))
	}
	return ""
}

// DownloadDBIPGzip downloads and decompresses a gzipped DB-IP MMDB with strict size limits.
func DownloadDBIPGzip(ctx context.Context, urlStr string) ([]byte, error) {
	reqCtx, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, urlStr, nil)
	if err != nil {
		return nil, err
	}
	resp, err := (&http.Client{Timeout: 120 * time.Second}).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download %s returned HTTP %d", urlStr, resp.StatusCode)
	}
	gzRaw, err := io.ReadAll(io.LimitReader(resp.Body, GeoIPMaxCompressed+1))
	if err != nil {
		return nil, err
	}
	if len(gzRaw) > GeoIPMaxCompressed {
		return nil, errors.New("compressed GeoIP database exceeds maximum allowed size")
	}
	gz, err := gzip.NewReader(bytes.NewReader(gzRaw))
	if err != nil {
		return nil, err
	}
	defer gz.Close()
	raw, err := io.ReadAll(io.LimitReader(gz, GeoIPMaxDBBytes+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > GeoIPMaxDBBytes {
		return nil, errors.New("decompressed GeoIP database exceeds maximum allowed size")
	}
	return raw, nil
}

// PublishGeoIPRelease writes an immutable release directory and atomically updates `current` symlink.
func PublishGeoIPRelease(dir, sourcePeriod string, mmdbBytes []byte, sel GeoIPSelection) (string, error) {
	byCountry, buildEpoch, err := ExtractCountryNetworks(mmdbBytes)
	if err != nil {
		return "", err
	}
	dbSum := sha256.Sum256(mmdbBytes)
	dbSHA := hex.EncodeToString(dbSum[:])

	var allowedLines []string
	countryCounts := make(map[string]int, len(sel.Countries))
	for _, code := range sel.Countries {
		nets := byCountry[code]
		countryCounts[code] = len(nets)
		allowedLines = append(allowedLines, nets...)
	}
	sort.Strings(allowedLines)
	allowedBytes := []byte(strings.Join(allowedLines, "\n"))
	if len(allowedLines) > 0 {
		allowedBytes = append(allowedBytes, '\n')
	}
	alSum := sha256.Sum256(allowedBytes)
	alSHA := hex.EncodeToString(alSum[:])

	releaseID := fmt.Sprintf("%s-%s", sourcePeriod, dbSHA[:12])
	relDir := filepath.Join(dir, "releases", releaseID)
	if err := os.MkdirAll(relDir, 0o755); err != nil {
		return "", err
	}
	if err := writeFileAtomic(filepath.Join(relDir, GeoIPDBName), mmdbBytes, 0o644); err != nil {
		return "", err
	}
	if err := writeFileAtomic(filepath.Join(relDir, GeoIPAllowedName), allowedBytes, 0o644); err != nil {
		return "", err
	}

	countryHashes := make(map[string]string, len(sel.Countries))
	for _, code := range sel.Countries {
		nets := byCountry[code]
		sort.Strings(nets)
		body := []byte(strings.Join(nets, "\n"))
		if len(nets) > 0 {
			body = append(body, '\n')
		}
		h := sha256.Sum256(body)
		fname := code + ".cidr"
		countryHashes[fname] = hex.EncodeToString(h[:])
		if err := writeFileAtomic(filepath.Join(relDir, fname), body, 0o644); err != nil {
			return "", err
		}
	}

	state := map[string]any{
		"release_format_version": GeoIPFormatVersion,
		"provider":               "dbip-country-lite",
		"source_period":          sourcePeriod,
		"activated_at":           time.Now().UTC().Format(time.RFC3339),
		"database_build_epoch":   buildEpoch,
		"database_sha256":        dbSHA,
		"allowed_sha256":         alSHA,
		"country_sha256":         countryHashes,
		"allowed_networks":       len(allowedLines),
		"country_networks":       countryCounts,
		"countries":              sel.Countries,
		"access_filter_enabled":  sel.AccessFilterEnabled,
	}
	stateRaw, _ := json.MarshalIndent(state, "", "  ")
	if err := writeFileAtomic(filepath.Join(relDir, GeoIPStateName), append(stateRaw, '\n'), 0o644); err != nil {
		return "", err
	}

	// Atomically swap the `current` symlink.
	tmpLink := filepath.Join(dir, fmt.Sprintf(".current.%d.tmp", time.Now().UnixNano()))
	_ = os.Remove(tmpLink)
	if err := os.Symlink(filepath.Join("releases", releaseID), tmpLink); err != nil {
		return "", err
	}
	if err := os.Rename(tmpLink, filepath.Join(dir, "current")); err != nil {
		_ = os.Remove(tmpLink)
		return "", err
	}
	return releaseID, nil
}
