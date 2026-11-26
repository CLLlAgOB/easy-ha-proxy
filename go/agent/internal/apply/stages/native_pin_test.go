package stages

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The native binaries come from the image CI built for the installed
// revision. The stage's own pull script runs here against a docker stand-in
// that knows the images in $IMAGES ("tag revision" lines), logs every call to
// $CALLS and fakes the bundle files.

const pinRevision = "0123456789abcdef0123456789abcdef01234567"

const fakeDockerForPull = `#!/bin/bash
echo "$*" >> "$CALLS"
digest() { printf '%s@sha256:%s' "${1%%:*}" "$(printf %s "$1" | sha256sum | cut -d' ' -f1)"; }
case "$1" in
  pull) grep -q "^$2 " "$IMAGES" && exit 0; exit 1 ;;
  image)
    fmt="$4"; img="$5"
    if [[ "$fmt" == *RepoDigests* ]]; then
      grep -q "^$img " "$IMAGES" || exit 1
      digest "$img"; echo; exit 0
    fi
    while read -r tag rev; do
      [ "$img" = "$(digest "$tag")" ] && { echo "$rev"; exit 0; }
    done < "$IMAGES"
    exit 1 ;;
  create) echo cid-1 ;;
  cp)
    src="${2#*:}"; dest="$3"; stage="$(dirname "$dest")"
    if [ "$src" = /SHA256SUMS ]; then
      (cd "$stage" && sha256sum sbin/* > "$dest")
    else
      mkdir -p "$dest"; printf %s "$src" > "$dest/easy-ha-proxy-agent"
    fi ;;
esac
exit 0
`

type pullRun struct {
	err    error
	stderr string
	calls  []string
	record map[string]string
}

type pullCase struct {
	images     map[string]string
	revisionRC int
	offline    bool
	verify     bool
	cosign     string // a cosign stand-in, "" for none on PATH
	imageName  string
}

func runPull(t *testing.T, c pullCase) pullRun {
	t.Helper()
	for _, tool := range []string{"bash", "sha256sum"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("needs %s", tool)
		}
	}
	root := t.TempDir()
	stage, bin := filepath.Join(root, "stage"), filepath.Join(root, "bin")
	os.MkdirAll(stage, 0o755)
	os.MkdirAll(bin, 0o755)
	os.WriteFile(filepath.Join(bin, "docker"), []byte(fakeDockerForPull), 0o755)
	if c.cosign != "" {
		os.WriteFile(filepath.Join(bin, "cosign"), []byte(c.cosign), 0o755)
	}
	var lines []string
	for tag, rev := range c.images {
		lines = append(lines, tag+" "+rev)
	}
	images := filepath.Join(root, "images")
	os.WriteFile(images, []byte(strings.Join(lines, "\n")+"\n"), 0o644)
	name := c.imageName
	if name == "" {
		name = "clllagob/haproxy-admin-ui:native-alpha"
	}
	b := &Builder{Set: mustSetWith(t, repoRoot(t), parts["native"], nil)}
	script, err := b.Set.RenderLocal(nativeOCIPull, map[string]any{
		"native_release_image": name, "easy_ha_proxy_offline_restore": c.offline, "native_release_verify_signature": c.verify,
		"native_release_cosign_identity_regexp": `^https://github\.com/CLLlAgOB/easy-ha-proxy/\.github/workflows/ci\.yml@refs/heads/(main|alpha)$`,
		"native_release_cosign_oidc_issuer":     "https://token.actions.githubusercontent.com",
		"_native_source_revision":               map[string]any{"rc": c.revisionRC, "stdout": pinRevision + "\n"},
	})
	if err != nil {
		t.Fatal(err)
	}
	script = strings.ReplaceAll(script, "/var/lib/easy-ha-proxy/native-staging", stage)
	calls := filepath.Join(root, "calls")
	cmd := exec.Command("bash", "-c", script)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	// cosign only from bin, never from the host.
	cmd.Env = append(os.Environ(), "PATH="+bin+":/usr/local/bin:/usr/bin:/bin", "IMAGES="+images, "CALLS="+calls)
	run := pullRun{err: cmd.Run(), stderr: stderr.String()}
	if raw, err := os.ReadFile(calls); err == nil {
		run.calls = strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	}
	if raw, err := os.ReadFile(filepath.Join(stage, "image.json")); err == nil {
		json.Unmarshal(raw, &run.record)
	}
	return run
}

func anyCall(calls []string, prefix string) bool {
	for _, c := range calls {
		if strings.HasPrefix(c, prefix) {
			return true
		}
	}
	return false
}

func TestTheCommitImageIsPulledCheckedAndCopiedByDigest(t *testing.T) {
	pinned := "clllagob/haproxy-admin-ui:native-alpha-" + pinRevision[:12]
	run := runPull(t, pullCase{images: map[string]string{pinned: pinRevision, "clllagob/haproxy-admin-ui:native-alpha": "other"}})
	if run.err != nil {
		t.Fatalf("%v: %s", run.err, run.stderr)
	}
	if !anyCall(run.calls, "pull "+pinned) || anyCall(run.calls, "pull clllagob/haproxy-admin-ui:native-alpha ") {
		t.Fatalf("calls %q", run.calls)
	}
	for _, c := range run.calls {
		if strings.HasPrefix(c, "create ") && !strings.Contains(c, "@sha256:") {
			t.Errorf("created by tag: %s", c)
		}
	}
	if run.record["image"] != pinned || run.record["revision"] != pinRevision ||
		!strings.HasPrefix(run.record["digest"], "clllagob/haproxy-admin-ui@sha256:") {
		t.Fatalf("record %v", run.record)
	}
}

func TestAnOfflineRestoreUsesOnlyTheCachedCommitImage(t *testing.T) {
	pinned := "clllagob/haproxy-admin-ui:native-alpha-" + pinRevision[:12]
	run := runPull(t, pullCase{images: map[string]string{pinned: pinRevision}, offline: true})
	if run.err != nil || anyCall(run.calls, "pull ") || !anyCall(run.calls, "create --pull=never ") {
		t.Fatalf("%v %q: %s", run.err, run.calls, run.stderr)
	}
	run = runPull(t, pullCase{images: map[string]string{}, offline: true})
	if run.err == nil || anyCall(run.calls, "pull ") || anyCall(run.calls, "create ") {
		t.Fatalf("without the image: %v %q", run.err, run.calls)
	}
}

func TestAnImageBuiltFromAnotherCommitIsRefused(t *testing.T) {
	pinned := "clllagob/haproxy-admin-ui:native-alpha-" + pinRevision[:12]
	run := runPull(t, pullCase{images: map[string]string{pinned: strings.Repeat("f", 40)}})
	if run.err == nil || !strings.Contains(run.stderr, "not "+pinRevision) || anyCall(run.calls, "create ") {
		t.Fatalf("%v %q: %s", run.err, run.calls, run.stderr)
	}
}

func TestAnUnpublishedCommitStopsRatherThanTakingTheChannelTag(t *testing.T) {
	run := runPull(t, pullCase{images: map[string]string{"clllagob/haproxy-admin-ui:native-alpha": "other"}})
	if run.err == nil || !strings.Contains(run.stderr, "not published") {
		t.Fatalf("%v: %s", run.err, run.stderr)
	}
	var pulls []string
	for _, c := range run.calls {
		if strings.HasPrefix(c, "pull ") {
			pulls = append(pulls, c)
		}
	}
	if strings.Join(pulls, ";") != "pull clllagob/haproxy-admin-ui:native-alpha-"+pinRevision[:12] {
		t.Fatalf("pulls %q", pulls)
	}
}

func TestWithoutAGitCheckoutTheChannelTagIsUsed(t *testing.T) {
	run := runPull(t, pullCase{images: map[string]string{"clllagob/haproxy-admin-ui:native-alpha": "whatever"}, revisionRC: 128})
	if run.err != nil || !anyCall(run.calls, "pull clllagob/haproxy-admin-ui:native-alpha") {
		t.Fatalf("%v %q: %s", run.err, run.calls, run.stderr)
	}
}

func TestSignatureVerificationFailsClosed(t *testing.T) {
	pinned := "clllagob/haproxy-admin-ui:native-alpha-" + pinRevision[:12]
	images := map[string]string{pinned: pinRevision}
	run := runPull(t, pullCase{images: images, verify: true})
	if run.err == nil || !strings.Contains(run.stderr, "cosign is not installed") || anyCall(run.calls, "create ") {
		t.Fatalf("missing cosign: %v %q: %s", run.err, run.calls, run.stderr)
	}
	run = runPull(t, pullCase{images: images, verify: true, cosign: "#!/bin/sh\necho 'invalid signature' >&2\nexit 1\n"})
	if run.err == nil || !strings.Contains(run.stderr, "invalid signature") || anyCall(run.calls, "create ") {
		t.Fatalf("bad signature: %v %q: %s", run.err, run.calls, run.stderr)
	}
	run = runPull(t, pullCase{images: images, verify: true, cosign: "#!/bin/sh\necho \"cosign $*\" >> \"$CALLS\"\nexit 0\n"})
	if run.err != nil || !anyCall(run.calls, "cosign verify ") || !anyCall(run.calls, "create ") || run.record["revision"] != pinRevision {
		t.Fatalf("good signature: %v %q: %s", run.err, run.calls, run.stderr)
	}
}
