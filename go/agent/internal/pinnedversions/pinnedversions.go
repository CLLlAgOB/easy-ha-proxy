// Package pinnedversions reports newer releases of the versions pinned in
// Ansible role defaults. Dependabot reads requirements files, Dockerfiles
// and workflows, but not the images and packages pinned as role variables
// (Authelia, Redis, the mail relay, the GeoIP packages). This compares each
// pin with its registry: the newest release in the same series (same
// major.minor, same suffix such as "-alpine") -- the update to take without
// much thought -- and the newest release overall, worth a look, may need
// care.
package pinnedversions

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

const IssueTitle = "Pinned versions have updates"

// Pin is (defaults file, variable, source, name). For a Docker Hub image
// given as a bare version the image name is here; a full reference carries
// its own.
type Pin struct {
	File, Variable, Source, Name string
}

var Pins = []Pin{
	{"ansible/roles/authelia/defaults/main.yml", "authelia_version", "dockerhub", "authelia/authelia"},
	{"ansible/roles/authelia/defaults/main.yml", "authelia_redis_image", "dockerhub", ""},
	{"ansible/roles/authelia/defaults/main.yml", "mail_relay_image", "dockerhub", ""},
}

var versionRe = regexp.MustCompile(`^v?(\d+(?:\.\d+)*)(-[A-Za-z0-9.]+)?$`)
var prereleaseRe = regexp.MustCompile(`(?i)(alpha|beta|rc|dev|pre|preview)`)

// ParseVersion is (numbers, suffix) for a release tag, or ok=false for
// anything else.
func ParseVersion(tag string) ([]int, string, bool) {
	m := versionRe.FindStringSubmatch(strings.TrimSpace(tag))
	if m == nil {
		return nil, "", false
	}
	suffix := m[2]
	if prereleaseRe.MatchString(suffix) {
		return nil, "", false
	}
	var numbers []int
	for _, part := range strings.Split(m[1], ".") {
		n, err := strconv.Atoi(part)
		if err != nil {
			return nil, "", false
		}
		numbers = append(numbers, n)
	}
	return numbers, suffix, true
}

func lessNumbers(a, b []int) bool {
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return len(a) < len(b)
}

func equalNumbers(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// NewerReleases is the newest release in the pinned series and the newest
// overall, both only if newer than the pin and of the same shape (part
// count, suffix); "" stands for none.
func NewerReleases(pinned string, tags []string) (series, latest string) {
	numbers, suffix, ok := ParseVersion(pinned)
	if !ok {
		return "", ""
	}
	type candidate struct {
		parts []int
		tag   string
	}
	var candidates []candidate
	for _, tag := range tags {
		found, foundSuffix, ok := ParseVersion(tag)
		if ok && foundSuffix == suffix && len(found) == len(numbers) && lessNumbers(numbers, found) {
			candidates = append(candidates, candidate{found, tag})
		}
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		if !equalNumbers(candidates[i].parts, candidates[j].parts) {
			return lessNumbers(candidates[i].parts, candidates[j].parts)
		}
		return candidates[i].tag < candidates[j].tag
	})
	for _, c := range candidates {
		if len(c.parts) >= 2 && len(numbers) >= 2 && equalNumbers(c.parts[:2], numbers[:2]) {
			series = c.tag
		}
	}
	if len(candidates) > 0 {
		latest = candidates[len(candidates)-1].tag
	}
	return series, latest
}

var pinRes = map[string]*regexp.Regexp{}

// ReadPin reads a role variable's scalar value out of a defaults file.
func ReadPin(text, variable string) string {
	re, ok := pinRes[variable]
	if !ok {
		re = regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(variable) + `:\s*['"]?([^'"\s#]+)`)
		pinRes[variable] = re
	}
	m := re.FindStringSubmatch(text)
	if m == nil {
		return ""
	}
	return m[1]
}

// SplitImage splits a full image reference into name and tag, as
// rpartition(":") does: without a colon the whole reference is the tag.
func SplitImage(reference string) (string, string) {
	i := strings.LastIndex(reference, ":")
	if i < 0 {
		return "", reference
	}
	return reference[:i], reference[i+1:]
}

// Fetch reads a registry URL as JSON.
type Fetch func(url string) (map[string]any, error)

// GetJSON is the registry fetch: a fixed https URL, a named client, 30s.
func GetJSON(url string) (map[string]any, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "easy-ha-proxy-pinned-versions")
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var data map[string]any
	if err := json.Unmarshal(raw, &data); err != nil {
		return nil, err
	}
	return data, nil
}

// DockerhubTags lists the repository's tags, newest first, up to pages.
func DockerhubTags(image string, fetch Fetch, pages int) ([]string, error) {
	namespace, repository := "", image
	if i := strings.LastIndex(image, "/"); i >= 0 {
		namespace, repository = image[:i], image[i+1:]
	}
	if namespace == "" {
		namespace = "library"
	}
	url := fmt.Sprintf("https://hub.docker.com/v2/namespaces/%s/repositories/%s/tags?page_size=100&ordering=last_updated",
		namespace, repository)
	var tags []string
	for i := 0; i < pages; i++ {
		data, err := fetch(url)
		if err != nil {
			return nil, err
		}
		results, _ := data["results"].([]any)
		for _, item := range results {
			if m, ok := item.(map[string]any); ok {
				tags = append(tags, fmt.Sprint(m["name"]))
			}
		}
		next, _ := data["next"].(string)
		if next == "" {
			break
		}
		url = next
	}
	return tags, nil
}

// PypiVersions lists the package's released versions.
func PypiVersions(packageName string, fetch Fetch) ([]string, error) {
	data, err := fetch("https://pypi.org/pypi/" + packageName + "/json")
	if err != nil {
		return nil, err
	}
	releases, _ := data["releases"].(map[string]any)
	var versions []string
	for v := range releases {
		versions = append(versions, v)
	}
	return versions, nil
}

// Row is one pin's comparison.
type Row struct {
	Variable, File, Pinned, Error, Name, Series, Latest string
}

// Check compares every pin with its registry; one registry down is a line,
// not a crash.
func Check(root string, fetch Fetch) []Row {
	var rows []Row
	for _, pin := range Pins {
		raw, err := os.ReadFile(root + "/" + pin.File)
		row := Row{Variable: pin.Variable, File: pin.File}
		if err != nil {
			row.Error = err.Error()
			rows = append(rows, row)
			continue
		}
		value := ReadPin(string(raw), pin.Variable)
		row.Pinned = value
		if value == "" {
			row.Error = "not found"
			rows = append(rows, row)
			continue
		}
		if pin.Source == "dockerhub" {
			image, pinned := pin.Name, value
			if image == "" {
				image, pinned = SplitImage(value)
			}
			row.Name, row.Pinned = image, pinned
			tags, err := DockerhubTags(image, fetch, 4)
			if err != nil {
				row.Error = truncError(err)
			} else {
				row.Series, row.Latest = NewerReleases(pinned, tags)
			}
		} else {
			row.Name = pin.Name
			versions, err := PypiVersions(pin.Name, fetch)
			if err != nil {
				row.Error = truncError(err)
			} else {
				row.Series, row.Latest = NewerReleases(value, versions)
			}
		}
		rows = append(rows, row)
	}
	return rows
}

func truncError(err error) string {
	s := err.Error()
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}

// Report is the Markdown table of the rows.
func Report(rows []Row) string {
	lines := []string{"| Pinned | Version | Same series | Newest |", "|---|---|---|---|"}
	for _, row := range rows {
		name := row.Name
		if name == "" {
			name = "?"
		}
		label := "`" + row.Variable + "`"
		if name != row.Variable {
			label += " (" + name + ")"
		}
		if row.Error != "" {
			pinned := row.Pinned
			if pinned == "" {
				pinned = "-"
			}
			lines = append(lines, fmt.Sprintf("| %s | %s | error: %s | |", label, pinned, row.Error))
			continue
		}
		series, latest := row.Series, row.Latest
		if series == "" {
			series = "-"
		}
		if latest == "" {
			latest = "-"
		}
		lines = append(lines, fmt.Sprintf("| %s | %s | %s | %s |", label, row.Pinned, series, latest))
	}
	return strings.Join(lines, "\n") + "\n"
}

// Behind says whether any pin has a newer release.
func Behind(rows []Row) bool {
	for _, row := range rows {
		if row.Series != "" || row.Latest != "" {
			return true
		}
	}
	return false
}

// SyncIssue keeps one open issue while anything is behind; closed once
// nothing is.
func SyncIssue(body string, outdated bool) error {
	out, err := exec.Command("gh", "issue", "list", "--state", "open",
		"--search", "in:title \""+IssueTitle+"\"", "--json", "number,title").Output()
	if err != nil {
		return err
	}
	var issues []struct {
		Number int    `json:"number"`
		Title  string `json:"title"`
	}
	if err := json.Unmarshal(out, &issues); err != nil {
		return err
	}
	var matching []int
	for _, issue := range issues {
		if issue.Title == IssueTitle {
			matching = append(matching, issue.Number)
		}
	}
	run := func(args ...string) error {
		cmd := exec.Command("gh", args...)
		cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
		return cmd.Run()
	}
	switch {
	case outdated && len(matching) > 0:
		return run("issue", "edit", strconv.Itoa(matching[0]), "--body", body)
	case outdated:
		return run("issue", "create", "--title", IssueTitle, "--body", body)
	default:
		for _, number := range matching {
			if err := run("issue", "close", strconv.Itoa(number),
				"--comment", "Every pinned version is current."); err != nil {
				return err
			}
		}
	}
	return nil
}
