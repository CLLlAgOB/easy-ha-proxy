package updateplan

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Newer upstream releases (U01): information only.
//
// The image checks say whether the pinned tag's content moved, and the
// source update says when the project pins a newer one. Neither says that
// upstream released something newer the project has not taken up yet. This
// does, for an allow-listed repository, and changes nothing: no pull, no new
// pin, no button. It sits outside the components, so it is not part of what
// an installation is held to.
//
// Only a plain release in the pinned tag's own flavour counts (8.10.3-alpine
// -> 8.12.0-alpine; not 8.12-alpine, not 8.12.0-rc1-alpine). Docker Hub's
// registry answers the whole tag list at once; a list it cuts short, or no
// answer, is "unknown", never "none".

const (
	upstreamTimeout  = 8 * time.Second
	upstreamMaxBytes = 1024 * 1024
)

var upstreamRepositories = map[string]string{"redis": "library/redis"}

// Fetcher gets a URL; the response headers come back with lower-case names.
type Fetcher func(url string, headers map[string]string) ([]byte, map[string]string, error)

// HTTPGet is the production Fetcher.
func HTTPGet(url string, headers map[string]string) ([]byte, map[string]string, error) {
	request, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, nil, err
	}
	request.Header.Set("User-Agent", "easy-ha-proxy")
	for k, v := range headers {
		request.Header.Set(k, v)
	}
	response, err := (&http.Client{Timeout: upstreamTimeout}).Do(request)
	if err != nil {
		return nil, nil, err
	}
	defer response.Body.Close()
	if response.StatusCode >= 400 {
		return nil, nil, fmt.Errorf("HTTP Error %d: %s", response.StatusCode, http.StatusText(response.StatusCode))
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, upstreamMaxBytes+1))
	if err != nil {
		return nil, nil, err
	}
	out := map[string]string{}
	for k, v := range response.Header {
		out[strings.ToLower(k)] = strings.Join(v, ", ")
	}
	return body, out, nil
}

// registryTags is every tag of a Docker Hub repository, and whether the list
// is whole.
func registryTags(repository string, fetch Fetcher) ([]string, bool, error) {
	tokenBody, _, err := fetch("https://auth.docker.io/token?service=registry.docker.io&scope=repository:"+repository+":pull",
		map[string]string{})
	if err != nil {
		return nil, false, err
	}
	var tokenReply struct {
		Token any `json:"token"`
	}
	if err := json.Unmarshal(tokenBody, &tokenReply); err != nil {
		return nil, false, err
	}
	token, _ := tokenReply.Token.(string)
	if token == "" {
		return nil, false, errors.New("the registry gave no token")
	}
	body, headers, err := fetch("https://registry-1.docker.io/v2/"+repository+"/tags/list?n=10000",
		map[string]string{"Authorization": "Bearer " + token})
	if err != nil {
		return nil, false, err
	}
	if len(body) > upstreamMaxBytes {
		return nil, false, nil
	}
	var listReply struct {
		Tags any `json:"tags"`
	}
	if err := json.Unmarshal(body, &listReply); err != nil {
		return nil, false, err
	}
	list, ok := listReply.Tags.([]any)
	if !ok {
		return nil, false, errors.New("the registry gave no tag list")
	}
	tags := []string{}
	for _, tag := range list {
		if s, ok := tag.(string); ok {
			tags = append(tags, s)
		}
	}
	// A Link header means there is another page this did not read.
	_, more := headers["link"]
	return tags, !more, nil
}

type releaseVersion [3]int

func (v releaseVersion) less(o releaseVersion) bool {
	for i := range v {
		if v[i] != o[i] {
			return v[i] < o[i]
		}
	}
	return false
}

func parseRelease(tag string) (releaseVersion, string, bool) {
	m := releaseTagRe.FindStringSubmatch(tag)
	if m == nil {
		return releaseVersion{}, "", false
	}
	var v releaseVersion
	for i := 0; i < 3; i++ {
		n, err := strconv.Atoi(m[i+1])
		if err != nil {
			return releaseVersion{}, "", false
		}
		v[i] = n
	}
	return v, m[4], true
}

// upstreamRelease is what upstream has beyond the pinned release of one
// image; nil when the image is not one this looks at.
func upstreamRelease(image, pinnedBy string, fetch Fetcher) M {
	repository := imageRepository(image)
	if repository == "" || strings.Contains(image, "@") {
		return nil
	}
	name := strings.TrimPrefix(strings.TrimPrefix(repository, "docker.io/"), "library/")
	hub, ok := upstreamRepositories[name]
	if !ok {
		return nil
	}
	tag := "latest"
	lastPart := image[strings.LastIndex(image, "/")+1:]
	if strings.Contains(lastPart, ":") {
		tag = image[strings.LastIndex(image, ":")+1:]
	}
	result := M{"image": image, "repository": name, "pinned_by": pinnedBy}
	current, flavour, ok := parseRelease(tag)
	if !ok {
		result["state"], result["reason"] = "unknown", "pin-is-not-a-release"
		return result
	}
	tags, complete, err := registryTags(hub, fetch)
	if err != nil {
		result["state"], result["reason"], result["error"] = "unknown", "registry-unavailable", truncRunes(redact(err.Error()), 200)
		return result
	}
	type release struct {
		version releaseVersion
		tag     string
	}
	newer := []release{}
	for _, candidate := range tags {
		if version, f, ok := parseRelease(candidate); ok && f == flavour && current.less(version) {
			newer = append(newer, release{version, candidate})
		}
	}
	sort.Slice(newer, func(i, j int) bool {
		if newer[i].version != newer[j].version {
			return newer[i].version.less(newer[j].version)
		}
		return newer[i].tag < newer[j].tag
	})
	var sameMajor, newest any
	for _, r := range newer {
		if r.version[0] == current[0] {
			sameMajor = r.tag
		}
	}
	if len(newer) > 0 {
		newest = newer[len(newer)-1].tag
	}
	result["current"], result["newest_same_major"], result["newest"], result["complete"] = tag, sameMajor, newest, complete
	switch {
	case len(newer) > 0:
		result["state"] = "newer"
	case complete:
		result["state"] = "none"
	default:
		result["state"], result["reason"] = "unknown", "tag-list-incomplete"
	}
	return result
}

func upstreamReleases(components []M, variables M, fetch Fetcher) []any {
	overridden := map[string]bool{}
	for _, v := range autheliaImageVariables {
		if s, ok := variables[v.variable].(string); ok {
			overridden[s] = true
		}
	}
	found := []any{}
	for _, c := range components {
		d, _ := c["details"].(M)
		images, _ := d["images"].([]any)
		for _, entry := range images {
			image := ""
			if detail, ok := entry.(M); ok {
				image = truthyStr(detail["image"])
			}
			pinnedBy := "project"
			if overridden[image] {
				pinnedBy = "override"
			}
			if release := upstreamRelease(image, pinnedBy, fetch); release != nil {
				release["component"] = c["id"]
				found = append(found, release)
			}
		}
	}
	return found
}
