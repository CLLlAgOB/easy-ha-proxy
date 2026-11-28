package tools

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"syscall"
	"time"
)

// A bounded APT metadata refresh for the update broker: apt-get update under
// a timeout, never a package install, and a record of the result the update
// checker reads (it treats the metadata as fresh for a day, and only while
// the APT sources are the ones the refresh saw).

const (
	AptMetadataState = "/var/lib/easy-ha-proxy/apt-metadata/status.json"
	aptMetadataMax   = 24 * 3600
)

var aptRepositoryURL = regexp.MustCompile(`https?://\S+`)

// aptGetPath is apt-get; the tests put a stand-in there.
var aptGetPath = "/usr/bin/apt-get"

// AptSourceFingerprint is the digest of every .list and .sources file.
func AptSourceFingerprint(root string) (string, error) {
	paths := []string{filepath.Join(root, "sources.list")}
	more, _ := filepath.Glob(filepath.Join(root, "sources.list.d", "*"))
	sort.Strings(more)
	paths = append(paths, more...)
	digest := sha256.New()
	for _, path := range paths {
		ext := filepath.Ext(path)
		fi, err := os.Stat(path)
		if (ext != ".list" && ext != ".sources") || err != nil || !fi.Mode().IsRegular() {
			continue
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return "", err
		}
		if len(data) > 1024*1024 {
			return "", errors.New("APT source file exceeds the metadata limit")
		}
		digest.Write([]byte(filepath.Base(path)))
		digest.Write([]byte{0})
		digest.Write(data)
		digest.Write([]byte{0})
	}
	return hex.EncodeToString(digest.Sum(nil)), nil
}

// AssessAptMetadata reads the record; "fresh" says whether it can be trusted.
func AssessAptMetadata(path, root string, now time.Time) map[string]any {
	unverified := map[string]any{"fresh": false, "success": false, "last_success": nil, "error": "APT metadata has not been verified"}
	fi, err := os.Lstat(path)
	if err != nil || fi.Mode()&os.ModeSymlink != 0 || fi.Size() > 64*1024 {
		return unverified
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return unverified
	}
	var data map[string]any
	if json.Unmarshal(raw, &data) != nil || data["format"] != 1.0 {
		return unverified
	}
	sources, err := AptSourceFingerprint(root)
	if err != nil {
		return unverified
	}
	success, isNumber := data["last_success"].(float64)
	age := float64(now.UnixNano())/1e9 - success
	data["fresh"] = data["success"] == true && isNumber && age >= 0 && age <= aptMetadataMax && data["sources"] == sources
	return data
}

// RefreshAptMetadata runs apt-get update (the caller holds the maintenance
// lock) and records the result.
func RefreshAptMetadata(path, root string, timeout time.Duration) (map[string]any, error) {
	previous := AssessAptMetadata(path, root, time.Now())
	before, err := AptSourceFingerprint(root)
	if err != nil {
		return nil, err
	}
	var failure any
	cmd := exec.Command(aptGetPath, "--error-on=any", "-o", "Acquire::Retries=1", "-o", "Acquire::http::Timeout=15",
		"-o", "Acquire::https::Timeout=15", "update")
	cmd.Env = append(os.Environ(), "LC_ALL=C", "DEBIAN_FRONTEND=noninteractive")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	var diagnostic bytes.Buffer
	cmd.Stdout = io.Discard
	cmd.Stderr = &diagnostic
	if err := cmd.Start(); err != nil {
		failure = fmt.Sprintf("APT metadata refresh failed: %v", err)
	} else {
		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()
		select {
		case err := <-done:
			if err != nil {
				code := -1
				var exit *exec.ExitError
				if errors.As(err, &exit) {
					code = exit.ExitCode()
				}
				msg := fmt.Sprintf("APT metadata refresh failed (exit %d)", code)
				// A small useful error, without URL credentials or tokens.
				var last string
				for _, line := range strings.Split(diagnostic.String(), "\n") {
					if strings.HasPrefix(line, "E:") || strings.HasPrefix(line, "W:") {
						last = line
					}
				}
				if last != "" {
					detail := aptRepositoryURL.ReplaceAllString(last, "[repository]")
					if len(detail) > 300 {
						detail = detail[:300]
					}
					msg += ": " + detail
				}
				failure = msg
			}
		case <-time.After(timeout):
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
				<-done
			}
			failure = "APT metadata refresh timed out"
		}
	}
	after, err := AptSourceFingerprint(root)
	if err != nil {
		return nil, err
	}
	if before != after {
		failure = "APT sources changed during metadata refresh"
	}
	now := float64(time.Now().UnixNano()) / 1e9
	lastSuccess := previous["last_success"]
	if failure == nil {
		lastSuccess = now
	}
	data := map[string]any{"format": 1, "success": failure == nil, "last_attempt": now, "last_success": lastSuccess,
		"sources": after, "error": failure}
	raw, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".status-*")
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return nil, err
	}
	if _, err := tmp.Write(raw); err != nil {
		tmp.Close()
		return nil, err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return nil, err
	}
	if err := tmp.Close(); err != nil {
		return nil, err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return nil, err
	}
	data["fresh"] = failure == nil
	return data, nil
}

// RunAptMetadata is "easy-ha-proxy-agent apt-metadata refresh".
func RunAptMetadata(args []string, stdout, stderr io.Writer) int {
	if len(args) != 1 || args[0] != "refresh" {
		fmt.Fprintln(stderr, "usage: easy-ha-proxy-agent apt-metadata refresh")
		return 2
	}
	if os.Geteuid() != 0 {
		fmt.Fprintln(stderr, "Package metadata refresh must run as root")
		return 2
	}
	result, err := RefreshAptMetadata(AptMetadataState, "/etc/apt", 100*time.Second)
	if err != nil {
		fmt.Fprintf(stderr, "APT metadata refresh: %v\n", err)
		return 1
	}
	raw, _ := json.Marshal(result)
	fmt.Fprintln(stdout, string(raw))
	return 0
}
