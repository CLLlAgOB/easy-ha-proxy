package fullbackup

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEncryptionRoundTrip(t *testing.T) {
	requireTools(t, "openssl")
	root := t.TempDir()
	source, encrypted, restored := filepath.Join(root, "source.bin"), filepath.Join(root, "backup.enc"), filepath.Join(root, "restored.bin")
	writeText(t, source, strings.Repeat("easy-ha-proxy backup test\n", 32))
	if err := opensslCrypt(source, encrypted, passphrase, false); err != nil {
		t.Fatal(err)
	}
	if readText(t, encrypted)[:4] != encMagic || readText(t, encrypted) == readText(t, source) {
		t.Fatal("not the EHP2 format")
	}
	if fi, _ := os.Stat(encrypted); fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", fi.Mode())
	}
	if err := opensslCrypt(encrypted, restored, passphrase, true); err != nil {
		t.Fatal(err)
	}
	if readText(t, restored) != readText(t, source) {
		t.Fatal("round trip changed the data")
	}
	// A wrong passphrase, and a damaged file, are told before OpenSSL runs.
	if err := opensslCrypt(encrypted, restored, "another passphrase", true); !isWrongPassphrase(err) {
		t.Fatalf("wrong passphrase: %v", err)
	}
	raw := []byte(readText(t, encrypted))
	raw[len(raw)-1] ^= 0xff
	damaged := filepath.Join(root, "damaged.enc")
	_ = os.WriteFile(damaged, raw, 0o600)
	if err := opensslCrypt(damaged, restored, passphrase, true); !isWrongPassphrase(err) {
		t.Fatalf("damaged: %v", err)
	}
	if entries, _ := os.ReadDir(root); len(entries) != 4 {
		t.Fatalf("scratch files left: %v", entries)
	}
}

func TestLegacyV1ArchivesStayReadable(t *testing.T) {
	requireTools(t, "openssl")
	root := t.TempDir()
	source, legacy, restored := filepath.Join(root, "source.bin"), filepath.Join(root, "legacy.enc"), filepath.Join(root, "restored.bin")
	writeText(t, source, "a v1 archive\n")
	if err := runOpenSSLEnc(source, legacy, passphrase, false); err != nil {
		t.Fatal(err)
	}
	if err := opensslCrypt(legacy, restored, passphrase, true); err != nil || readText(t, restored) != "a v1 archive\n" {
		t.Fatalf("legacy: %v", err)
	}
}

func TestABackupIsEncryptedWithItsManifest(t *testing.T) {
	requireTools(t, "openssl", "tar")
	root := t.TempDir()
	config := installedHost(t, root)
	_ = config
	data := filepath.Join(root, "data")
	writeText(t, filepath.Join(data, "secret.txt"), "secret\n")
	swap(t, &corePaths, []string{data})
	swap(t, &coreGlobs, nil)
	swap(t, &coreDirectoryPaths, map[string]bool{data: true})
	withStdin(t, passphrase+"\n")
	swap(t, &term.getpass, func(string) (string, error) { t.Fatal("getpass must not be used"); return "", nil })
	var encrypted string
	output := captureStdout(t, func() {
		var err error
		encrypted, err = createBackup(backupOptions{outputDir: filepath.Join(root, "backups"), passphraseStdin: true})
		if err != nil {
			t.Error(err)
		}
	})
	if encrypted == "" {
		t.Fatal("no archive")
	}
	decrypted, extracted := filepath.Join(root, "decrypted.tar.gz"), filepath.Join(root, "extracted")
	_ = os.Mkdir(extracted, 0o700)
	if err := opensslCrypt(encrypted, decrypted, passphrase, true); err != nil {
		t.Fatal(err)
	}
	if err := extractBundle(decrypted, extracted); err != nil {
		t.Fatal(err)
	}
	var manifest map[string]any
	if err := json.Unmarshal([]byte(readText(t, filepath.Join(extracted, "manifest.json"))), &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest["format_version"] != 1.0 || !sameJSON(t, manifest["core_paths"], []string{data}) ||
		!sameJSON(t, manifest["runtime_excludes"], backupExcludes) || manifest["ssh_included"] != false ||
		manifest["payload_expanded_bytes"] != 7.0 || manifest["ssh_payload_expanded_bytes"] != nil {
		t.Fatalf("manifest %v", manifest)
	}
	marker := "EASY_HA_PROXY_BACKUP_MANIFEST_JSON="
	var lines []string
	for _, line := range splitLines(output) {
		if strings.HasPrefix(line, marker) {
			lines = append(lines, line)
		}
	}
	var printed map[string]any
	if len(lines) != 1 || json.Unmarshal([]byte(lines[0][len(marker):]), &printed) != nil || !sameJSON(t, printed, manifest) {
		t.Fatalf("marker %v", lines)
	}
	if !strings.Contains(output, "EASY_HA_PROXY_FULL_BACKUP_FILE="+encrypted+"\n") {
		t.Fatalf("output %q", output)
	}
	sum, _ := sha256File(encrypted)
	if readText(t, encrypted+".sha256") != sum+"  "+filepath.Base(encrypted)+"\n" {
		t.Fatal("sidecar")
	}
	if fi, _ := os.Stat(filepath.Dir(encrypted)); fi.Mode().Perm() != 0o700 {
		t.Fatalf("backup directory mode %v", fi.Mode())
	}
}

func TestABackupNeedsAnInstallation(t *testing.T) {
	requireTools(t, "openssl", "tar")
	root := t.TempDir()
	t.Setenv("EASY_HA_PROXY_ALLOW_NON_ROOT", "1")
	t.Setenv("EASY_HA_PROXY_CONFIG_DIR", filepath.Join(root, "missing"))
	if _, err := createBackup(backupOptions{outputDir: filepath.Join(root, "backups")}); err == nil ||
		!strings.Contains(err.Error(), "installation was not found") {
		t.Fatalf("err %v", err)
	}
}

func inspectWithStdin(t *testing.T, encrypted string) (map[string]any, string, error) {
	t.Helper()
	withStdin(t, passphrase+"\n")
	var manifest map[string]any
	var err error
	output := captureStdout(t, func() { manifest, err = inspectBackup(encrypted, true) })
	return manifest, output, err
}

func TestInspectPrintsOneCompactManifestMarker(t *testing.T) {
	root := t.TempDir()
	encrypted, expected := createTestArchive(t, root, archiveSpec{})
	before, _ := os.ReadDir(root)
	swap(t, &term.getpass, func(string) (string, error) { t.Fatal("getpass must not be used"); return "", nil })
	manifest, output, err := inspectWithStdin(t, encrypted)
	if err != nil {
		t.Fatal(err)
	}
	lines := splitLines(output)
	prefix := "EASY_HA_PROXY_BACKUP_MANIFEST_JSON="
	var printed map[string]any
	if len(lines) != 1 || !strings.HasPrefix(lines[0], prefix) || json.Unmarshal([]byte(lines[0][len(prefix):]), &printed) != nil {
		t.Fatalf("output %q", output)
	}
	if !sameJSON(t, printed, expected) || !sameJSON(t, manifest, expected) {
		t.Fatalf("manifest %v", printed)
	}
	if after, _ := os.ReadDir(root); len(after) != len(before) {
		t.Fatal("inspect left files beside the archive")
	}
}

func TestInspectEnrichesAnOlderV1Manifest(t *testing.T) {
	encrypted, original := createTestArchive(t, t.TempDir(), archiveSpec{omitExpanded: true})
	manifest, _, err := inspectWithStdin(t, encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if _, found := original["payload_expanded_bytes"]; found {
		t.Fatal("the archive had sizes")
	}
	if n, _ := integer(manifest["payload_expanded_bytes"]); n != int64(len("managed state\n")) || manifest["ssh_payload_expanded_bytes"] != nil {
		t.Fatalf("manifest %v", manifest)
	}
}

func TestInspectRefusesWhatDoesNotAddUp(t *testing.T) {
	for _, tc := range []struct {
		name    string
		spec    archiveSpec
		message string
	}{
		{"declared size", archiveSpec{manifestUpdates: map[string]any{"payload_expanded_bytes": 1}}, "expanded-size verification"},
		{"ssh checksum", archiveSpec{includeSSH: true, sshChecksum: strings.Repeat("0", 64)}, "SSH payload checksum"},
		{"core member", archiveSpec{coreEntries: []tarEntry{file("etc/shadow", "root:*:0:0\n")}}, "outside managed paths"},
		{"manifest core path", archiveSpec{manifestUpdates: map[string]any{"core_paths": []any{"/etc"}}}, "unmanaged core_paths"},
		{"ssh member", archiveSpec{includeSSH: true, sshEntries: []tarEntry{file("etc/shadow", "not an SSH key\n")}}, "outside allowed paths"},
		{"duplicate outer", archiveSpec{duplicateOuter: "manifest.json"}, "Duplicate outer backup"},
		{"unknown outer", archiveSpec{extraOuter: &tarEntry{name: "unexpected.txt", content: "unexpected\n"}}, "Unexpected outer"},
		{"format", archiveSpec{manifestUpdates: map[string]any{"format_version": 2}}, "Unsupported full-backup format"},
		{"float size", archiveSpec{manifestUpdates: map[string]any{"payload_expanded_bytes": 14.5}}, "payload_expanded_bytes"},
		{"ssh inconsistent", archiveSpec{manifestUpdates: map[string]any{"ssh_included": true}}, "SSH metadata is inconsistent"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			encrypted, _ := createTestArchive(t, t.TempDir(), tc.spec)
			if _, _, err := inspectWithStdin(t, encrypted); err == nil || !strings.Contains(err.Error(), tc.message) {
				t.Fatalf("err %v", err)
			}
		})
	}
}

func TestAChangedArchiveFailsItsChecksum(t *testing.T) {
	encrypted, _ := createTestArchive(t, t.TempDir(), archiveSpec{})
	writeText(t, encrypted+".sha256", strings.Repeat("a", 64)+"  x\n")
	if _, _, err := inspectWithStdin(t, encrypted); err == nil || !strings.Contains(err.Error(), "checksum verification failed") {
		t.Fatalf("err %v", err)
	}
	if err := verifyEncryptedArchive(encrypted + ".missing"); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("missing: %v", err)
	}
}
