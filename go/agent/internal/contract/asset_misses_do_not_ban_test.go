package contract

import (
	"regexp"
	"strings"
	"testing"
)

// A missing logo must not get anyone banned: a link preview fetching thirty
// absent icons pushed src_http_err_rate over the site limit and earned a
// week-long ban (ban_code=10) without a single attack path. The error
// counters now skip static assets through the err_asset_path acl. The list
// is deliberately narrower than the adaptive engine's: .json, .xml and .txt
// stay counted, because /config.json and /.env.txt are plausible probes and
// tracking is decided from the path before the response status is known.

const assetMissTemplate = "ansible/roles/haproxy/templates/haproxy.cfg.j2"

// assetMissAclLines is every declaration of the err_asset_path acl.
func assetMissAclLines(t *testing.T) []string {
	t.Helper()
	var lines []string
	for _, line := range strings.Split(read(t, assetMissTemplate), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "acl err_asset_path") {
			lines = append(lines, line)
		}
	}
	return lines
}

var assetMissSuffixRe = regexp.MustCompile(`\.[a-z0-9]+`)

// assetMissSuffixes is the set of suffixes the acl matches, read from the
// part of each declaration after "-i".
func assetMissSuffixes(t *testing.T) map[string]bool {
	t.Helper()
	found := map[string]bool{}
	for _, line := range assetMissAclLines(t) {
		parts := strings.SplitN(line, "-i", 2)
		if len(parts) != 2 {
			t.Fatalf("acl line has no -i: %s", line)
		}
		for _, suffix := range assetMissSuffixRe.FindAllString(parts[1], -1) {
			found[suffix] = true
		}
	}
	return found
}

func TestAssetAclIsDeclared(t *testing.T) {
	if len(assetMissAclLines(t)) == 0 {
		t.Fatal("no err_asset_path acl in the template")
	}
}

func TestAssetAclMatchesOnTheEndOfThePath(t *testing.T) {
	// path_beg would exempt /css-admin/, and a regex would cost a match
	// per request for no gain.
	for _, line := range assetMissAclLines(t) {
		if !strings.Contains(line, "path_end") {
			t.Errorf("%.50s: not a path_end match", strings.TrimSpace(line))
		}
	}
}

func TestAssetAclCoversEverythingThatCausedTheBan(t *testing.T) {
	suffixes := assetMissSuffixes(t)
	for _, suffix := range []string{".png", ".svg", ".ico", ".gif"} {
		if !suffixes[suffix] {
			t.Errorf("err_asset_path does not cover %s", suffix)
		}
	}
}

func TestAssetAclCoversTheRestOfTheOrdinaryAssetTypes(t *testing.T) {
	suffixes := assetMissSuffixes(t)
	for _, suffix := range []string{".css", ".js", ".map", ".woff2", ".jpg", ".webp"} {
		if !suffixes[suffix] {
			t.Errorf("err_asset_path does not cover %s", suffix)
		}
	}
}

func TestAssetAclDoesNotForgiveThePlausibleTargets(t *testing.T) {
	// Wider than the engine here would be a way to hide from the counter
	// by naming a probe /config.json or /.env.txt.
	suffixes := assetMissSuffixes(t)
	for _, suffix := range []string{".json", ".xml", ".txt", ".php", ".env", ".sql"} {
		if suffixes[suffix] {
			t.Errorf("err_asset_path forgives %s", suffix)
		}
	}
}

func TestPerSiteCounterSkipsAssets(t *testing.T) {
	mustContain(t, read(t, assetMissTemplate),
		"set-var(txn.site_{{ id }}_excl) bool(true) if err_asset_path",
		"haproxy.cfg.j2")
}

func TestCatchAllCounterSkipsAssets(t *testing.T) {
	mustContain(t, read(t, assetMissTemplate),
		"set-var(txn.other_excl) bool(true) if err_asset_path",
		"haproxy.cfg.j2")
}

func TestAssetExclusionIsSetAfterTheFlagIsCleared(t *testing.T) {
	// bool(false) then bool(true): the other way round clears it again and
	// the whole thing does nothing, which is exactly how err_exclude spent
	// months doing nothing.
	source := read(t, assetMissTemplate)
	for _, variable := range []string{"txn.other_excl", "txn.site_{{ id }}_excl"} {
		cleared := strings.Index(source, "set-var("+variable+") bool(false)")
		asset := strings.Index(source, "set-var("+variable+") bool(true) if err_asset_path")
		if cleared < 0 || asset < 0 {
			t.Errorf("%s: missing the clear or the asset exclusion", variable)
			continue
		}
		if cleared >= asset {
			t.Errorf("%s: the asset exclusion is set before the flag is cleared", variable)
		}
	}
}

func TestConfiguredExclusionStillWorksAlongsideIt(t *testing.T) {
	// The per-site err_exclude rules must still be rendered; the asset
	// rule is an addition, not a replacement.
	mustContain(t, read(t, assetMissTemplate),
		"site_{{ id }}_ex{{ rule }}_path",
		"haproxy.cfg.j2")
}
