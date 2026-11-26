package updateplan

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// serviceSourcePaths are the host-service inputs of the source tree.
var serviceSourcePaths = []string{
	"go/agent",
	"rust/guardd",
	"ansible/easy-ha-proxy.yml",
	"ansible/roles/authelia",
	"ansible/roles/cert",
	"ansible/roles/docker",
	"ansible/roles/geoip_acl",
	"ansible/roles/haproxy",
	"ansible/roles/haproxy-admin",
	"ansible/roles/healthcheck",
}

const nativeStagingMetadata = "/var/lib/easy-ha-proxy/native-staging/image.json"

var nativeDaemonArtifacts = []struct{ id, label, installed, source string }{
	{"easy-ha-proxy-agent", "Native Go host agent", "/usr/local/sbin/easy-ha-proxy-agent", "go/agent"},
	{"guardd-core", "Native Rust adaptive protection engine", "/usr/local/sbin/guardd-core", "rust/guardd"},
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	digest := sha256.New()
	if _, err := io.Copy(digest, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(digest.Sum(nil)), nil
}

// treeFiles lists the regular files (symlinked ones included) below dir by
// their path relative to root, as pathlib's rglob does: symlinked
// directories are not descended into, unreadable ones are passed over.
func treeFiles(root, dir string, skip func(relative string) bool, files map[string]string) {
	_ = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if fi, err := os.Stat(path); err != nil || !fi.Mode().IsRegular() {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return nil
		}
		relative := filepath.ToSlash(rel)
		if !skip(relative) {
			files[relative] = path
		}
		return nil
	})
}

func hasSegment(relative string, names ...string) bool {
	wrapped := "/" + relative + "/"
	for _, name := range names {
		if strings.Contains(wrapped, "/"+name+"/") {
			return true
		}
	}
	return false
}

// filesDigest hashes "relative\0sha256\0" for every file in path order; ""
// when there are none or one cannot be read.
func filesDigest(files map[string]string) string {
	if len(files) == 0 {
		return ""
	}
	names := make([]string, 0, len(files))
	for relative := range files {
		names = append(names, relative)
	}
	sort.Strings(names)
	digest := sha256.New()
	for _, relative := range names {
		sum, err := fileSHA256(files[relative])
		if err != nil {
			return ""
		}
		digest.Write([]byte(relative))
		digest.Write([]byte{0})
		digest.Write([]byte(sum))
		digest.Write([]byte{0})
	}
	return hex.EncodeToString(digest.Sum(nil))
}

func serviceFingerprint(root string) string {
	files := map[string]string{}
	for _, selected := range serviceSourcePaths {
		path := filepath.Join(root, filepath.FromSlash(selected))
		if isFile(path) {
			files[selected] = path
			continue
		}
		if !isDir(path) {
			continue
		}
		treeFiles(root, path, func(relative string) bool {
			return hasSegment(relative, "__pycache__", "target", "dist") || strings.HasSuffix(relative, ".pyc") ||
				strings.HasSuffix(relative, "haproxy-admin.zip")
		}, files)
	}
	return filesDigest(files)
}

func dirFingerprint(root, relDir string) string {
	target := filepath.Join(root, filepath.FromSlash(relDir))
	if !isDir(target) {
		return ""
	}
	files := map[string]string{}
	treeFiles(root, target, func(relative string) bool {
		return hasSegment(relative, "target", "dist", "__pycache__")
	}, files)
	return filesDigest(files)
}

func probeServices(source M, channel, installedSource, candidateSource, candidateError string) M {
	if channel == "local" {
		return component("services", "blocked", "Remote host-service checks are disabled for the local source channel.",
			nil, nil, M{"reason": "local-source-channel", "network_checked": false})
	}
	current, available := source["current_version"], source["available_version"]
	switch str(source["state"]) {
	case "available":
		if candidateSource == "" {
			return component("services", "unknown", "The remote source changed, but its host-service files could not be classified.",
				current, available, M{"reason": "source-diff-unclassified", "candidate_error": orNil(candidateError),
					"depends_on": "all"})
		}
		installed, candidate := serviceFingerprint(installedSource), serviceFingerprint(candidateSource)
		if installed == "" || candidate == "" {
			return component("services", "unknown", "Host-service source files could not be fingerprinted.",
				orNil(installed), orNil(candidate), M{"reason": "service-fingerprint-unavailable", "depends_on": "all"})
		}
		if installed == candidate {
			return component("services", "current", "The remote source does not change host-service files.",
				installed, candidate, M{"depends_on": "all"})
		}
		return component("services", "available", "The remote source contains different host-service files.",
			installed, candidate, M{"reason": "source-update", "depends_on": "all"})
	case "current":
		return component("services", "current", "Host services are based on the current managed source revision.",
			current, available, M{"depends_on": "all"})
	case "blocked":
		return component("services", "blocked", "Host-service updates are blocked until the source issue is resolved.",
			current, available, M{"reason": "source-blocked", "depends_on": "all"})
	}
	return component("services", "unknown", "Host-service updates could not be determined because the source state is unknown.",
		current, available, M{"reason": "source-unknown", "depends_on": "all"})
}

func readNativeMetadata(path string) M {
	if !isFile(path) {
		return nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var data any
	if json.Unmarshal(raw, &data) != nil {
		return nil
	}
	m, _ := data.(M)
	return m
}

type daemonOptions struct {
	artifactPath            func(string) string
	remoteCandidateRequired bool
	candidateError          string
	installedSource         string
	targetRevision          string
}

func probeDaemons(sourceDir string, o daemonOptions) M {
	resolve := o.artifactPath
	if resolve == nil {
		resolve = func(path string) string { return path }
	}
	installedRev := ""
	if meta := readNativeMetadata(resolve(nativeStagingMetadata)); meta != nil {
		if raw, ok := meta["revision"].(string); ok {
			raw = strings.ToLower(strings.TrimSpace(raw))
			if revisionFullRe.MatchString(raw) {
				installedRev = raw
			}
		}
	}
	targetRev := strings.ToLower(strings.TrimSpace(o.targetRevision))
	if !revisionFullRe.MatchString(targetRev) {
		targetRev = ""
	}
	baseSource := o.installedSource
	if baseSource == "" {
		baseSource = sourceDir
	}
	artifacts := []any{}
	available, checked := false, 0
	sourceChanged := map[string]bool{}
	for _, a := range nativeDaemonArtifacts {
		installed := resolve(a.installed)
		item := M{"id": a.id, "label": a.label, "native": true}
		changed, known := sourceChanged[a.source]
		if !known {
			if baseSource != sourceDir {
				old, now := dirFingerprint(baseSource, a.source), dirFingerprint(sourceDir, a.source)
				changed = old != "" && now != "" && old != now
			}
			sourceChanged[a.source] = changed
		}
		checked++
		switch {
		case !isFile(installed):
			item["state"], item["reason"] = "available", "installed-file-missing"
			available = true
		case changed:
			item["state"], item["reason"] = "available", "native-source-changed"
			item["current_revision"], item["available_revision"] = orNil(installedRev), orNil(targetRev)
			available = true
		case targetRev != "" && installedRev != targetRev:
			item["state"] = "available"
			item["reason"] = "native-metadata-missing"
			if installedRev != "" {
				item["reason"] = "revision-mismatch"
			}
			item["current_revision"], item["available_revision"] = orNil(installedRev), targetRev
			available = true
		default:
			item["state"] = "current"
			item["current_revision"] = orNil(installedRev)
			if targetRev != "" {
				item["available_revision"] = targetRev
			} else {
				item["available_revision"] = orNil(installedRev)
			}
		}
		artifacts = append(artifacts, item)
	}
	d := M{"comparison": "installed-files-to-managed-source", "artifacts": artifacts}
	total := len(artifacts)
	if o.remoteCandidateRequired {
		return component("daemons", "unknown", "The remote source changed, but its helper daemon files could not be compared safely.",
			fmt.Sprintf("%d/%d checked locally", checked, total), nil,
			merged(d, M{"reason": "remote-candidate-unavailable", "candidate_error": orNil(o.candidateError)}))
	}
	if available {
		outdated := []string{}
		current, updates := 0, 0
		for _, entry := range artifacts {
			item := entry.(M)
			switch item["state"] {
			case "available":
				outdated = append(outdated, item["label"].(string))
				updates++
			case "current":
				current++
			}
		}
		message := "One or more helper daemons differ from the managed source."
		if len(outdated) > 0 {
			message = "Helper daemons to update: " + strings.Join(outdated, ", ")
		}
		return component("daemons", "available", message, fmt.Sprintf("%d/%d", current, total),
			fmt.Sprintf("%d updates", updates), d)
	}
	if checked == 0 {
		return component("daemons", "blocked", "Helper daemon source files are unavailable.", nil, nil,
			merged(d, M{"reason": "daemon-sources-missing"}))
	}
	return component("daemons", "current", "Installed helper daemons match the managed source.",
		fmt.Sprintf("%d/%d current", checked, total), fmt.Sprintf("%d/%d current", checked, total), d)
}

func probeOS(runner Runner, freshness M, excluded map[string]bool) M {
	result := runner.Run([]string{"apt-get", "-s", "upgrade"}, aptTimeout)
	if result.Returncode != 0 {
		state := "unknown"
		if result.Error == "not-found" {
			state = "blocked"
		}
		return component("os", state, "Upgradeable operating-system packages could not be checked.", nil, nil,
			M{"reason": "apt-simulation-failed", "error": shortError(result)})
	}
	packages := []string{}
	candidates := []any{}
	seen := map[string]bool{}
	for _, line := range splitLines(result.Stdout) {
		if !strings.HasPrefix(line, "Inst ") {
			continue
		}
		match := aptInstLineRe.FindStringSubmatch(line)
		if match == nil {
			return component("os", "unknown", "An operating-system package candidate could not be parsed safely from the APT simulation.",
				nil, nil, M{"reason": "apt-candidate-unparseable", "line": truncRunes(redact(line), 512)})
		}
		name := match[aptInstLineRe.SubexpIndex("name")]
		version := match[aptInstLineRe.SubexpIndex("version")]
		var installed any
		if idx := aptInstLineRe.SubexpIndex("installed"); aptGroupMatched(line, idx) {
			installed = match[idx]
		}
		base, _, _ := strings.Cut(name, ":")
		if excluded[base] {
			continue
		}
		if !seen[name] {
			packages = append(packages, name)
			candidates = append(candidates, M{"name": name, "version": version, "installed_version": installed})
			seen[name] = true
		}
	}
	if freshness != nil && freshness["fresh"] != true {
		return component("os", "unknown", "APT metadata is stale or its refresh failed. Check for updates again.", nil, nil,
			M{"apt": freshness, "packages": strList(packages), "candidates": candidates})
	}
	if len(packages) > 0 {
		return component("os", "available", fmt.Sprintf("%d operating-system package update(s) are available.", len(packages)),
			nil, len(packages), M{"package_count": len(packages), "packages": strList(packages), "candidates": candidates})
	}
	return component("os", "current", "No operating-system package updates are present in the current APT cache.", 0, 0,
		M{"package_count": 0, "packages": []any{}, "candidates": []any{}})
}

// aptGroupMatched says whether the optional group took part in the match
// (Python's None for a group that did not).
func aptGroupMatched(line string, group int) bool {
	loc := aptInstLineRe.FindStringSubmatchIndex(line)
	return loc != nil && loc[2*group] >= 0
}
