package contract

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// installer/agent-fetch.sh: how a host without an agent gets its first one.
// Run with bash and a stand-in curl and uname on PATH; the "release" is a
// directory the stand-in curl serves from.

const fetchRevision = "0123456789abcdef0123456789abcdef01234567"

var fetchAgent = []byte("#!/bin/sh\necho agent\n")

const fakeCurl = `#!/bin/sh
# Records its arguments; serves -o FILE URL from $RELEASE by the URL's name.
echo "$@" >> "$CALLS"
out="" url=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    -o) out="$2"; shift 2 ;;
    -*) case "$1" in --proto|--proto-redir|--retry|--connect-timeout|--max-time) shift ;; esac; shift ;;
    *) url="$1"; shift ;;
  esac
done
file="$RELEASE/${url##*/}"
[ -f "$file" ] || exit 22
cp "$file" "$out"
`

type fetchFixture struct {
	t           *testing.T
	root        string
	bin         string
	release     string
	source      string
	config      string
	calls       string
	destination string
}

func newFetchFixture(t *testing.T) *fetchFixture {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("needs a POSIX host")
	}
	for _, tool := range []string{"bash", "tar", "sha256sum"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skip("needs " + tool)
		}
	}
	root := t.TempDir()
	f := &fetchFixture{t: t, root: root,
		bin:         filepath.Join(root, "bin"),
		release:     filepath.Join(root, "release"),
		source:      filepath.Join(root, "source"),
		config:      filepath.Join(root, "etc"),
		calls:       filepath.Join(root, "calls"),
		destination: filepath.Join(root, "staging", "bootstrap", "easy-ha-proxy-agent"),
	}
	for _, dir := range []string{f.bin, f.release, f.source, f.config} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for name, body := range map[string]string{"curl": fakeCurl, "uname": "#!/bin/sh\necho x86_64\n"} {
		if err := os.WriteFile(filepath.Join(f.bin, name), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	f.writeRevision(fetchRevision)
	return f
}

func (f *fetchFixture) writeRevision(revision string) {
	f.t.Helper()
	if err := os.WriteFile(filepath.Join(f.source, ".easy-ha-proxy-source-revision"),
		[]byte("revision="+revision+"\n"), 0o644); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fetchFixture) publish(binary []byte, checksum string) {
	f.t.Helper()
	name := "easy-ha-proxy-agent-" + fetchRevision + "-linux-amd64"
	if err := os.WriteFile(filepath.Join(f.release, name), binary, 0o644); err != nil {
		f.t.Fatal(err)
	}
	if checksum == "" {
		sum := sha256.Sum256(binary)
		checksum = hex.EncodeToString(sum[:])
	}
	if err := os.WriteFile(filepath.Join(f.release, name+".sha256"),
		[]byte(checksum+"  "+name+"\n"), 0o644); err != nil {
		f.t.Fatal(err)
	}
}

type fetchResult struct {
	code   int
	stdout string
	stderr string
}

func (f *fetchFixture) fetch() fetchResult {
	f.t.Helper()
	script := `source "` + filepath.Join(repoRoot(f.t), "installer", "agent-fetch.sh") + `"; easy_ha_proxy_fetch_agent "$1" "$2"`
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "bash", "-c", script, "fetch", f.source, f.destination)
	cmd.Env = []string{
		"PATH=" + f.bin + ":/usr/bin:/bin",
		"RELEASE=" + f.release,
		"CALLS=" + f.calls,
		"EASY_HA_PROXY_CONFIG_DIR=" + f.config,
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	code := 0
	if err != nil {
		if exit, ok := err.(*exec.ExitError); ok {
			code = exit.ExitCode()
		} else {
			f.t.Fatal(err)
		}
	}
	return fetchResult{code, stdout.String(), stderr.String()}
}

func (f *fetchFixture) curlCalls() []string {
	f.t.Helper()
	raw, err := os.ReadFile(f.calls)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		f.t.Fatal(err)
	}
	return strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
}

func (f *fetchFixture) writeBundle(members [][2]string) {
	f.t.Helper()
	bundles := filepath.Join(f.root, "bundles")
	if err := os.MkdirAll(bundles, 0o755); err != nil {
		f.t.Fatal(err)
	}
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, m := range members {
		if err := tw.WriteHeader(&tar.Header{Name: m[0], Mode: 0o755, Size: int64(len(m[1]))}); err != nil {
			f.t.Fatal(err)
		}
		if _, err := tw.Write([]byte(m[1])); err != nil {
			f.t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		f.t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		f.t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bundles, "easy-ha-proxy-native-linux-amd64.tar.gz"), buf.Bytes(), 0o644); err != nil {
		f.t.Fatal(err)
	}
}

func TestTheAgentOfTheSourceRevisionIsDownloadedAndChecked(t *testing.T) {
	f := newFetchFixture(t)
	f.publish(fetchAgent, "")
	result := f.fetch()
	if result.code != 0 {
		t.Fatalf("rc %d: %s", result.code, result.stderr)
	}
	raw, err := os.ReadFile(f.destination)
	if err != nil || string(raw) != string(fetchAgent) {
		t.Fatalf("the agent was not installed: %v", err)
	}
	fi, _ := os.Stat(f.destination)
	if fi.Mode().Perm() != 0o755 {
		t.Fatalf("agent mode %o", fi.Mode().Perm())
	}
	if _, err := os.Lstat(f.destination + ".partial"); !os.IsNotExist(err) {
		t.Fatal("the partial file was left behind")
	}
	base := "https://github.com/CLLlAgOB/easy-ha-proxy/releases/download/agent-builds"
	name := "easy-ha-proxy-agent-" + fetchRevision + "-linux-amd64"
	var urls []string
	for _, call := range f.curlCalls() {
		fields := strings.Fields(call)
		urls = append(urls, fields[len(fields)-1])
	}
	want := []string{base + "/" + name, base + "/" + name + ".sha256"}
	if strings.Join(urls, ",") != strings.Join(want, ",") {
		t.Fatalf("curl urls %v", urls)
	}
	mustContain(t, result.stderr, fetchRevision[:12], "fetch stderr")
}

func TestABinaryThatDoesNotMatchItsChecksumIsNotInstalled(t *testing.T) {
	for _, checksum := range []string{strings.Repeat("0", 64), "not-a-checksum"} {
		f := newFetchFixture(t)
		f.publish(fetchAgent, checksum)
		result := f.fetch()
		if result.code != 1 {
			t.Errorf("%s: rc %d, want 1", checksum, result.code)
		}
		mustContain(t, result.stderr, "does not match its published SHA-256", checksum)
		if _, err := os.Lstat(f.destination); !os.IsNotExist(err) {
			t.Errorf("%s: the agent was installed", checksum)
		}
	}
}

func TestAgentFetchUsesConfiguredHTTPSBundleChecksum(t *testing.T) {
	f := newFetchFixture(t)
	f.writeBundle([][2]string{{"sbin/easy-ha-proxy-agent", string(fetchAgent)}})
	name := "easy-ha-proxy-native-linux-amd64.tar.gz"
	archive, err := os.ReadFile(filepath.Join(f.root, "bundles", name))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.release, name), archive, 0o600); err != nil {
		t.Fatal(err)
	}
	checksum := sha256.Sum256(archive)
	vars := "native_release_base_url: https://releases.example.test/native\nnative_release_checksums:\n  amd64: '" + hex.EncodeToString(checksum[:]) + "'\n"
	if err := os.WriteFile(filepath.Join(f.config, "vars.yml"), []byte(vars), 0o600); err != nil {
		t.Fatal(err)
	}
	result := f.fetch()
	if result.code != 0 {
		t.Fatalf("rc %d: %s", result.code, result.stderr)
	}
	if calls := f.curlCalls(); len(calls) != 1 || !strings.HasSuffix(calls[0], "/native/"+name) {
		t.Fatalf("curl: %v", calls)
	}
	if binary, err := os.ReadFile(f.destination); err != nil || !bytes.Equal(binary, fetchAgent) {
		t.Fatalf("agent = %q, %v", binary, err)
	}
}

func TestAgentFetchRequiresSignatureBeforeDockerExtraction(t *testing.T) {
	f := newFetchFixture(t)
	ref := "clllagob/haproxy-admin-ui@sha256:" + strings.Repeat("1", 64)
	docker := `#!/bin/sh
case "$1:$2" in
  pull:--) ;;
  image:inspect) printf '%s\n' '` + ref + `' ;;
  *) echo "unexpected Docker extraction" >> "$CALLS"; exit 1 ;;
esac
`
	cosign := `#!/bin/sh
printf '%s\n' "$*" >> "$CALLS"
exit 1
`
	for name, body := range map[string]string{"docker": docker, "cosign": cosign} {
		if err := os.WriteFile(filepath.Join(f.bin, name), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(f.config, "vars.yml"), []byte("'native_release_verify_signature': true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	result := f.fetch()
	if result.code == 0 {
		t.Fatal("installed agent after signature verification failed")
	}
	if calls := f.curlCalls(); len(calls) != 1 || !strings.HasSuffix(calls[0], " -- "+ref) {
		t.Fatalf("expected only verification of the immutable OCI digest, got %v", calls)
	}
}

func TestABuildNotYetPublishedSaysSo(t *testing.T) {
	f := newFetchFixture(t)
	result := f.fetch()
	if result.code != 1 {
		t.Fatalf("rc %d, want 1", result.code)
	}
	mustContain(t, result.stderr, "could not be downloaded", "fetch stderr")
	mustContain(t, result.stderr, "CI publishes it", "fetch stderr")
	if _, err := os.Lstat(f.destination); !os.IsNotExist(err) {
		t.Fatal("the agent was installed")
	}
}

func TestASourceOfUnknownRevisionIsRefused(t *testing.T) {
	f := newFetchFixture(t)
	f.writeRevision("main")
	result := f.fetch()
	if result.code != 1 {
		t.Fatalf("rc %d, want 1", result.code)
	}
	mustContain(t, result.stderr, "cannot tell which revision", "fetch stderr")
	if calls := f.curlCalls(); len(calls) != 0 {
		t.Fatalf("curl was called: %v", calls)
	}
}

func TestAHostWithALocalBundleTakesTheAgentFromIt(t *testing.T) {
	f := newFetchFixture(t)
	f.writeBundle([][2]string{
		{"./sbin/easy-ha-proxy-agent", string(fetchAgent)},
		{"./sbin/guardd-core", "guardd\n"},
	})
	bundles := filepath.Join(f.root, "bundles")
	if err := os.WriteFile(filepath.Join(f.config, "vars.yml"),
		[]byte("haproxy_admin_image: x\nnative_local_bundle_dir: \""+bundles+"\"  # offline\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Neither the revision nor the network is needed.
	if err := os.Remove(filepath.Join(f.source, ".easy-ha-proxy-source-revision")); err != nil {
		t.Fatal(err)
	}
	result := f.fetch()
	if result.code != 0 {
		t.Fatalf("rc %d: %s", result.code, result.stderr)
	}
	if raw, _ := os.ReadFile(f.destination); string(raw) != string(fetchAgent) {
		t.Fatal("the agent did not come from the bundle")
	}
	if calls := f.curlCalls(); len(calls) != 0 {
		t.Fatalf("curl was called: %v", calls)
	}
}

func TestALocalBundleWithoutTheAgentIsRefused(t *testing.T) {
	f := newFetchFixture(t)
	f.writeBundle([][2]string{{"sbin/guardd-core", "x"}})
	bundles := filepath.Join(f.root, "bundles")
	if err := os.WriteFile(filepath.Join(f.config, "vars.yml"),
		[]byte("native_local_bundle_dir: "+bundles+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	result := f.fetch()
	if result.code != 1 {
		t.Fatalf("rc %d, want 1", result.code)
	}
	mustContain(t, result.stderr, "holds no sbin/easy-ha-proxy-agent", "fetch stderr")
	if _, err := os.Lstat(f.destination); !os.IsNotExist(err) {
		t.Fatal("the agent was installed")
	}
}
