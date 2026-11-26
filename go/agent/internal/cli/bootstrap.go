package cli

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const (
	// DefaultRegistry is the OCI registry serving native agent scratch images.
	DefaultRegistry = "https://registry-1.docker.io"
	// DefaultAuthURL is the Docker Hub pull-token endpoint format.
	DefaultAuthURL = "https://auth.docker.io/token?service=registry.docker.io&scope=repository:%s:pull"
	// AgentMember is the archive path of the agent binary inside native bundles.
	AgentMember = "sbin/easy-ha-proxy-agent"
	// MaxBootstrapBlobBytes limits downloaded blobs to 256 MiB.
	MaxBootstrapBlobBytes = 256 * 1024 * 1024
)

var (
	bootstrapRegistry   = DefaultRegistry
	bootstrapAuthURL    = DefaultAuthURL
	bootstrapHTTPClient = &http.Client{Timeout: 60 * time.Second}
	bootstrapArchFunc   = defaultArchitecture
)

const bootstrapAcceptHeader = "application/vnd.oci.image.index.v1+json, " +
	"application/vnd.docker.distribution.manifest.list.v2+json, " +
	"application/vnd.oci.image.manifest.v1+json, " +
	"application/vnd.docker.distribution.manifest.v2+json"

// BootstrapError is an expected failure while fetching or verifying the host agent.
type BootstrapError struct {
	Msg string
}

func (e *BootstrapError) Error() string { return e.Msg }

func bootstrapErrorf(format string, args ...any) error {
	return &BootstrapError{Msg: fmt.Sprintf(format, args...)}
}

func defaultArchitecture() (string, error) {
	switch runtime.GOARCH {
	case "amd64", "arm64":
		return runtime.GOARCH, nil
	default:
		return "", bootstrapErrorf("unsupported architecture %s", runtime.GOARCH)
	}
}

// Architecture returns the normalized Linux architecture ("amd64" or "arm64").
func Architecture() (string, error) {
	return bootstrapArchFunc()
}

// ImageReference returns the pinned native OCI image reference for variables and
// revision, or "" when binaries come from a local bundle or HTTPS release.
func ImageReference(variables map[string]any, revision string) string {
	if strVal(variables["native_local_bundle_dir"]) != "" || strVal(variables["native_release_base_url"]) != "" {
		return ""
	}
	image := strVal(variables["haproxy_admin_image"])
	if image == "" {
		image = "clllagob/haproxy-admin-ui:latest"
	}
	channel := "latest"
	if strings.HasSuffix(image, ":alpha") || strings.HasSuffix(image, ":go-alpha") {
		channel = "alpha"
	}
	reference := strVal(variables["native_release_image"])
	if reference == "" || strings.Contains(reference, "{{") {
		reference = "clllagob/haproxy-admin-ui:native-" + channel
	}
	pin := true
	if raw, ok := variables["native_release_pin_revision"]; ok && raw != nil {
		lower := strings.ToLower(strings.TrimSpace(fmt.Sprint(raw)))
		if lower == "false" || lower == "0" || lower == "no" {
			pin = false
		}
	}
	if revision != "" && pin {
		prefix := revision
		if len(prefix) > 12 {
			prefix = prefix[:12]
		}
		reference += "-" + prefix
	}
	return reference
}

func registryGet(url, token, accept string) ([]byte, string, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("User-Agent", Product)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	resp, err := bootstrapHTTPClient.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, "", bootstrapErrorf("%s: HTTP %d", url, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxBootstrapBlobBytes+1))
	if err != nil {
		return nil, "", err
	}
	if len(body) > MaxBootstrapBlobBytes {
		return nil, "", bootstrapErrorf("%s: larger than %d bytes", url, MaxBootstrapBlobBytes)
	}
	return body, resp.Header.Get("Content-Type"), nil
}

// FetchAgent downloads and verifies the agent binary from an OCI registry image.
func FetchAgent(reference, revision, arch string) ([]byte, error) {
	name, tag, _ := strings.Cut(reference, ":")
	repo := name
	if !strings.Contains(repo, "/") {
		repo = "library/" + repo
	}
	if arch == "" {
		var err error
		arch, err = Architecture()
		if err != nil {
			return nil, err
		}
	}
	authURL := fmt.Sprintf(bootstrapAuthURL, repo)
	tokenBody, _, err := registryGet(authURL, "", "")
	if err != nil {
		return nil, err
	}
	var tokenResp struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(tokenBody, &tokenResp); err != nil {
		return nil, bootstrapErrorf("invalid registry auth response: %v", err)
	}
	token := tokenResp.Token

	body, _, err := registryGet(fmt.Sprintf("%s/v2/%s/manifests/%s", bootstrapRegistry, repo, tag), token, bootstrapAcceptHeader)
	if err != nil {
		return nil, err
	}
	var manifest map[string]any
	if err := json.Unmarshal(body, &manifest); err != nil {
		return nil, bootstrapErrorf("invalid manifest JSON for %s: %v", reference, err)
	}
	if manifests, ok := manifest["manifests"].([]any); ok {
		chosenDigest := ""
		for _, item := range manifests {
			m, _ := item.(map[string]any)
			platform, _ := m["platform"].(map[string]any)
			if strVal(platform["os"]) == "linux" && strVal(platform["architecture"]) == arch {
				chosenDigest = strVal(m["digest"])
				break
			}
		}
		if chosenDigest == "" {
			return nil, bootstrapErrorf("%s has no linux/%s image", reference, arch)
		}
		body, _, err = registryGet(fmt.Sprintf("%s/v2/%s/manifests/%s", bootstrapRegistry, repo, chosenDigest), token, bootstrapAcceptHeader)
		if err != nil {
			return nil, err
		}
		manifest = nil
		if err := json.Unmarshal(body, &manifest); err != nil {
			return nil, bootstrapErrorf("invalid platform manifest JSON for %s: %v", reference, err)
		}
	}

	cfgObj, _ := manifest["config"].(map[string]any)
	cfgDigest := strVal(cfgObj["digest"])
	if cfgDigest == "" {
		return nil, bootstrapErrorf("%s manifest has no config digest", reference)
	}
	cfgBody, _, err := registryGet(fmt.Sprintf("%s/v2/%s/blobs/%s", bootstrapRegistry, repo, cfgDigest), token, "")
	if err != nil {
		return nil, err
	}
	var cfgDoc struct {
		Config struct {
			Labels map[string]string `json:"Labels"`
		} `json:"config"`
	}
	if err := json.Unmarshal(cfgBody, &cfgDoc); err != nil {
		return nil, bootstrapErrorf("invalid config blob JSON for %s: %v", reference, err)
	}
	built := cfgDoc.Config.Labels["org.opencontainers.image.revision"]
	if revision != "" && built != revision {
		display := built
		if display == "" {
			display = "an unknown revision"
		}
		return nil, bootstrapErrorf("%s was built from %s, not %s", reference, display, revision)
	}

	files := map[string][]byte{}
	layers, _ := manifest["layers"].([]any)
	for _, item := range layers {
		layerObj, _ := item.(map[string]any)
		layerDigest := strVal(layerObj["digest"])
		blob, _, err := registryGet(fmt.Sprintf("%s/v2/%s/blobs/%s", bootstrapRegistry, repo, layerDigest), token, "")
		if err != nil {
			return nil, err
		}
		_, expectedHex, _ := strings.Cut(layerDigest, ":")
		if sha256Hex(blob) != expectedHex {
			return nil, bootstrapErrorf("layer %s does not match its digest", layerDigest)
		}
		if err := extractMembersFromTar(blob, files, AgentMember, "SHA256SUMS"); err != nil {
			return nil, err
		}
	}
	agentBytes, hasAgent := files[AgentMember]
	sumsBytes, hasSums := files["SHA256SUMS"]
	if !hasAgent || !hasSums {
		return nil, bootstrapErrorf("%s holds no %s with SHA256SUMS", reference, AgentMember)
	}
	if err := verifyAgentChecksum(agentBytes, string(sumsBytes), reference); err != nil {
		return nil, err
	}
	return agentBytes, nil
}

func verifyAgentChecksum(agentBytes []byte, sumsText, reference string) error {
	expected := map[string]string{}
	for _, line := range strings.Split(sumsText, "\n") {
		parts := strings.Fields(line)
		if len(parts) == 2 {
			member := strings.TrimLeft(strings.TrimPrefix(parts[1], "*"), "./")
			expected[member] = strings.ToLower(parts[0])
		}
	}
	want, ok := expected[AgentMember]
	if !ok {
		return bootstrapErrorf("SHA256SUMS in %s does not list %s", reference, AgentMember)
	}
	if sha256Hex(agentBytes) != want {
		return bootstrapErrorf("%s does not match SHA256SUMS in %s", AgentMember, reference)
	}
	return nil
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func extractMembersFromTar(raw []byte, dst map[string][]byte, wanted ...string) error {
	wantedSet := make(map[string]bool, len(wanted))
	for _, w := range wanted {
		wantedSet[w] = true
	}
	var reader io.Reader = bytes.NewReader(raw)
	if len(raw) >= 2 && raw[0] == 0x1f && raw[1] == 0x8b {
		gz, err := gzip.NewReader(reader)
		if err != nil {
			return err
		}
		defer gz.Close()
		reader = gz
	}
	tr := tar.NewReader(reader)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		if hdr.Typeflag != tar.TypeReg && hdr.Typeflag != tar.TypeRegA {
			continue
		}
		clean := strings.TrimLeft(hdr.Name, "./")
		if wantedSet[clean] {
			data, err := io.ReadAll(io.LimitReader(tr, MaxBootstrapBlobBytes+1))
			if err != nil {
				return err
			}
			if len(data) > MaxBootstrapBlobBytes {
				return bootstrapErrorf("%s exceeds maximum allowed size", clean)
			}
			dst[clean] = data
		}
	}
	return nil
}

func agentFromTarball(raw []byte) ([]byte, error) {
	files := map[string][]byte{}
	if err := extractMembersFromTar(raw, files, AgentMember); err != nil {
		return nil, err
	}
	agent, ok := files[AgentMember]
	if !ok {
		return nil, bootstrapErrorf("the bundle holds no %s", AgentMember)
	}
	return agent, nil
}

// BundleAgent returns the agent from a local bundle or HTTPS release with
// pinned checksum, or (nil, nil) when neither is configured.
func BundleAgent(variables map[string]any, arch string) ([]byte, error) {
	if arch == "" {
		var err error
		arch, err = Architecture()
		if err != nil {
			return nil, err
		}
	}
	name := fmt.Sprintf("easy-ha-proxy-native-linux-%s.tar.gz", arch)
	if local := strVal(variables["native_local_bundle_dir"]); local != "" {
		raw, err := os.ReadFile(filepath.Join(local, name))
		if err != nil {
			return nil, err
		}
		return agentFromTarball(raw)
	}
	base := strVal(variables["native_release_base_url"])
	if base == "" {
		return nil, nil
	}
	if !strings.HasPrefix(base, "https://") {
		return nil, bootstrapErrorf("native_release_base_url must be an https:// URL")
	}
	checksum := ""
	switch m := variables["native_release_checksums"].(type) {
	case map[string]any:
		checksum = strings.ToLower(strVal(m[arch]))
	case map[string]string:
		checksum = strings.ToLower(m[arch])
	}
	if len(checksum) != 64 {
		return nil, bootstrapErrorf("native_release_checksums has no SHA-256 for %s", arch)
	}
	raw, _, err := registryGet(strings.TrimRight(base, "/")+"/"+name, "", "")
	if err != nil {
		return nil, err
	}
	if sha256Hex(raw) != checksum {
		return nil, bootstrapErrorf("%s does not match native_release_checksums", name)
	}
	return agentFromTarball(raw)
}

// DockerAgent extracts and verifies the agent from an already-loaded local
// Docker image (used during offline restores). Returns (nil, nil) if Docker or
// the image is unavailable.
func DockerAgent(reference, revision string) ([]byte, error) {
	docker, err := lookPath("docker")
	if err != nil || docker == "" {
		return nil, nil
	}
	out, rc, err := captureCommand(docker, "image", "inspect", "--format",
		`{{ index .Config.Labels "org.opencontainers.image.revision" }}`, reference)
	if err != nil || rc != 0 {
		return nil, nil
	}
	built := strings.TrimSpace(out)
	if revision != "" && built != revision {
		display := built
		if display == "" {
			display = "an unknown revision"
		}
		return nil, bootstrapErrorf("%s was built from %s, not %s", reference, display, revision)
	}
	createdOut, rc, err := captureCommand(docker, "create", "--pull=never", reference)
	if err != nil || rc != 0 {
		return nil, nil
	}
	container := strings.TrimSpace(createdOut)
	defer func() {
		_, _, _ = captureCommand(docker, "rm", "-f", container)
	}()
	tmpDir, err := os.MkdirTemp("", "easy-ha-proxy-docker-agent.")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmpDir)
	for _, member := range []string{"/sbin/easy-ha-proxy-agent", "/SHA256SUMS"} {
		if _, cpRC, cpErr := captureCommand(docker, "cp", container+":"+member, tmpDir); cpErr != nil || cpRC != 0 {
			return nil, bootstrapErrorf("docker cp %s failed", member)
		}
	}
	agentBytes, err := os.ReadFile(filepath.Join(tmpDir, "easy-ha-proxy-agent"))
	if err != nil {
		return nil, err
	}
	sumsBytes, err := os.ReadFile(filepath.Join(tmpDir, "SHA256SUMS"))
	if err != nil {
		return nil, err
	}
	if err := verifyAgentChecksum(agentBytes, string(sumsBytes), reference); err != nil {
		return nil, err
	}
	return agentBytes, nil
}

// InstallAgent writes the binary atomically to destination with mode 0755.
func InstallAgent(binary []byte, destination string) error {
	if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(destination), ".easy-ha-proxy-agent.*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpPath)
		}
	}()
	if _, err := tmp.Write(binary); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpPath, 0o755); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, destination); err != nil {
		return err
	}
	cleanup = false
	return nil
}

func captureCommand(name string, args ...string) (string, int, error) {
	cmd := exec.Command(name, args...)
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	err := cmd.Run()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return stdout.String(), ee.ExitCode(), nil
		}
		return stdout.String(), 1, err
	}
	return stdout.String(), 0, nil
}

func strVal(v any) string {
	if v == nil {
		return ""
	}
	return fmt.Sprint(v)
}
