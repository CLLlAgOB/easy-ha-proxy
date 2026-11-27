package hostfile

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadRegularRefusesOversizeAndSymlinks(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.yml")
	if err := os.WriteFile(path, []byte("settings"), 0o600); err != nil {
		t.Fatal(err)
	}
	if data, err := ReadRegular(path, 8); err != nil || string(data) != "settings" {
		t.Fatalf("read = %q, %v", data, err)
	}
	if _, err := ReadRegular(path, 7); err == nil {
		t.Fatal("accepted an oversized file")
	}
	link := filepath.Join(dir, "link.yml")
	alias := filepath.Join(dir, "alias")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(dir, alias); err != nil {
		t.Fatal(err)
	}
	for _, candidate := range []string{link, filepath.Join(alias, "settings.yml")} {
		if _, err := ReadRegular(candidate, 8); err == nil {
			t.Errorf("followed %s", candidate)
		}
	}
}
