package fullbackup

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

const passphrase = "correct horse battery"

func swap[T any](t *testing.T, target *T, value T) {
	t.Helper()
	old := *target
	*target = value
	t.Cleanup(func() { *target = old })
}

func repoRoot() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "..", "..", "..")
}

func requireTools(t *testing.T, tools ...string) {
	t.Helper()
	for _, tool := range tools {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s is not installed", tool)
		}
	}
}

// withStdin makes the console read these lines.
func withStdin(t *testing.T, text string) {
	t.Helper()
	swap(t, &term.stdin, bufio.NewReader(strings.NewReader(text)))
}

// captureStdout runs fn and returns what it printed.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	saved := os.Stdout
	os.Stdout = writer
	done := make(chan string)
	go func() {
		raw, _ := io.ReadAll(reader)
		done <- string(raw)
	}()
	defer func() { os.Stdout = saved }()
	fn()
	writer.Close()
	os.Stdout = saved
	return <-done
}

type tarEntry struct {
	name    string
	content string
	typ     byte
	link    string
	mode    int64
	pax     map[string]string
}

func file(name, content string) tarEntry {
	return tarEntry{name: name, content: content, typ: tar.TypeReg}
}

func writeTar(t *testing.T, p string, entries []tarEntry) {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, e := range entries {
		mode := e.mode
		if mode == 0 {
			mode = 0o644
		}
		typ := e.typ
		if typ == 0 {
			typ = tar.TypeReg
		}
		h := &tar.Header{Name: e.name, Typeflag: typ, Linkname: e.link, Mode: mode, PAXRecords: e.pax}
		if typ == tar.TypeReg {
			h.Size = int64(len(e.content))
		}
		if len(e.pax) > 0 {
			h.Format = tar.FormatPAX
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if typ == tar.TypeReg {
			if _, err := tw.Write([]byte(e.content)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
}

func writeText(t *testing.T, p, text string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(text), 0o644); err != nil {
		t.Fatal(err)
	}
}

func readText(t *testing.T, p string) string {
	t.Helper()
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

type archiveSpec struct {
	includeSSH      bool
	sshChecksum     string
	manifestUpdates map[string]any
	coreEntries     []tarEntry
	sshEntries      []tarEntry
	duplicateOuter  string
	extraOuter      *tarEntry
	omitExpanded    bool
}

func entriesSize(entries []tarEntry) int {
	n := 0
	for _, e := range entries {
		n += len(e.content)
	}
	return n
}

// createTestArchive builds an encrypted archive the way a backup does,
// returning it and its manifest.
func createTestArchive(t *testing.T, root string, spec archiveSpec) (string, map[string]any) {
	t.Helper()
	requireTools(t, "openssl")
	payload := filepath.Join(root, "payload.tar.gz")
	core := spec.coreEntries
	if core == nil {
		core = []tarEntry{file("etc/easy-ha-proxy/state.txt", "managed state\n")}
	}
	writeTar(t, payload, core)
	sshPayload := filepath.Join(root, "ssh.tar.gz")
	ssh := spec.sshEntries
	if ssh == nil {
		ssh = []tarEntry{file("root/.ssh/authorized_keys", "ssh-ed25519 test-key\n")}
	}
	if spec.includeSSH {
		writeTar(t, sshPayload, ssh)
	}
	payloadSHA, _ := sha256File(payload)
	manifest := map[string]any{
		"format": "easy-ha-proxy-full-backup", "format_version": FormatVersion, "created_at": "20260718T120000Z",
		"hostname": "proxy.example.test", "machine": "x86_64", "core_paths": []any{"/etc/easy-ha-proxy"},
		"runtime_excludes": anyList(backupExcludes), "ssh_included": spec.includeSSH, "ssh_paths": []any{},
		"quiesced": true, "payload_sha256": payloadSHA, "ssh_payload_sha256": nil,
		"payload_expanded_bytes": entriesSize(core), "ssh_payload_expanded_bytes": nil,
	}
	if spec.includeSSH {
		manifest["ssh_paths"] = []any{"/root/.ssh"}
		sum, _ := sha256File(sshPayload)
		if spec.sshChecksum != "" {
			sum = spec.sshChecksum
		}
		manifest["ssh_payload_sha256"] = sum
		manifest["ssh_payload_expanded_bytes"] = entriesSize(ssh)
	}
	if spec.omitExpanded {
		delete(manifest, "payload_expanded_bytes")
		delete(manifest, "ssh_payload_expanded_bytes")
	}
	for k, v := range spec.manifestUpdates {
		manifest[k] = v
	}
	manifestJSON, _ := json.Marshal(manifest)
	members := []tarEntry{file("manifest.json", string(manifestJSON)), file("system-state.txt", "test system\n"),
		file("payload.tar.gz", readText(t, payload))}
	if spec.includeSSH {
		members = append(members, file("ssh.tar.gz", readText(t, sshPayload)))
	}
	for _, m := range members {
		if m.name == spec.duplicateOuter {
			members = append(members, m)
			break
		}
	}
	if spec.extraOuter != nil {
		members = append(members, *spec.extraOuter)
	}
	bundle := filepath.Join(root, "bundle.tar.gz")
	writeTar(t, bundle, members)
	encrypted := filepath.Join(root, "easy-ha-proxy-full-test.tar.gz.enc")
	if err := encryptBackup(bundle, encrypted, passphrase); err != nil {
		t.Fatal(err)
	}
	sum, _ := sha256File(encrypted)
	writeText(t, encrypted+".sha256", sum+"  "+filepath.Base(encrypted)+"\n")
	return encrypted, manifest
}

func anyList(values []string) []any {
	out := make([]any, len(values))
	for i, v := range values {
		out[i] = v
	}
	return out
}

// sameJSON compares two values as their JSON says.
func sameJSON(t *testing.T, a, b any) bool {
	t.Helper()
	normalize := func(v any) any {
		raw, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		var out any
		_ = json.Unmarshal(raw, &out)
		return out
	}
	return reflect.DeepEqual(normalize(a), normalize(b))
}

// recorder stands in for the commands, answering from a handler.
type recorder struct {
	calls   [][]string
	handler func(argv []string) (runResult, error)
}

func record(t *testing.T, handler func(argv []string) (runResult, error)) *recorder {
	t.Helper()
	r := &recorder{handler: handler}
	real := runCommand
	swap(t, &runCommand, func(argv []string, o runOptions) (runResult, error) {
		if r.handler == nil && argv[0] == "openssl" {
			// Decrypting the test archive is real.
			return real(argv, o)
		}
		r.calls = append(r.calls, append([]string(nil), argv...))
		if r.handler == nil {
			return runResult{}, nil
		}
		return r.handler(argv)
	})
	return r
}

func (r *recorder) ran(argv ...string) bool {
	for _, call := range r.calls {
		if reflect.DeepEqual(call, argv) {
			return true
		}
	}
	return false
}

// fakeQuiesce records what a restore asks of the quiesce.
type fakeQuiesce struct {
	events *[]string
}

func (f fakeQuiesce) enter() error {
	*f.events = append(*f.events, "quiesce-entered")
	return nil
}
func (f fakeQuiesce) resumeUnits() { *f.events = append(*f.events, "quiesce-units-resumed") }
func (f fakeQuiesce) exit()        { *f.events = append(*f.events, "quiesce-exited") }

func quietQuiesce(t *testing.T) *[]string {
	t.Helper()
	events := &[]string{}
	swap(t, &newQuiesce, func(bool, bool) quiescer {
		*events = append(*events, "quiesce-created")
		return fakeQuiesce{events}
	})
	return events
}

// installedHost is a configuration directory that says easy-ha-proxy is
// installed, and the variables a test restore runs with.
func installedHost(t *testing.T, root string) string {
	t.Helper()
	config := filepath.Join(root, "config")
	writeText(t, filepath.Join(config, "metadata.yml"), "mode: production\n")
	swap(t, &requireRoot, func() error { return nil })
	t.Setenv("EASY_HA_PROXY_CONFIG_DIR", config)
	swap(t, &metricsSnapshot, filepath.Join(root, "no-history", "metrics.db"))
	swap(t, &metricsDatabase, filepath.Join(root, "metrics", "metrics.db"))
	swap(t, &DefaultBackupRoot, filepath.Join(root, "backups"))
	return config
}
