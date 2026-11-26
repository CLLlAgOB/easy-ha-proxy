package fullbackup

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
)

// BackupError is an expected backup or restore failure.
type BackupError struct{ msg string }

func (e *BackupError) Error() string { return e.msg }

func backupErrorf(format string, args ...any) error {
	return &BackupError{fmt.Sprintf(format, args...)}
}

// WrongPassphrase is an archive that did not open with the passphrase given.
type WrongPassphrase struct{ BackupError }

func wrongPassphrase() error {
	return &WrongPassphrase{BackupError{"Cannot decrypt backup: wrong passphrase or damaged file."}}
}

func isWrongPassphrase(err error) bool {
	var w *WrongPassphrase
	return errors.As(err, &w)
}

// errCancelled is Ctrl+C: a restore still rolls back on it.
var errCancelled = errors.New("Cancelled.")

var interrupted atomic.Bool

func checkInterrupt() error {
	if interrupted.Load() {
		return errCancelled
	}
	return nil
}

// CommandError is a command that exited with a non-zero status.
type CommandError struct {
	Argv           []string
	Code           int
	Stdout, Stderr string
}

func (e *CommandError) Error() string {
	return fmt.Sprintf("Command '%s' returned non-zero exit status %d.", strings.Join(e.Argv, " "), e.Code)
}

// runOptions: capture collects the output, input is written to stdin and env
// replaces the environment.
type runOptions struct {
	check   bool
	capture bool
	input   string
	env     []string
}

type runResult struct {
	Code           int
	Stdout, Stderr string
}

// runCommand runs argv; the tests replace it. Without capture the command
// writes to this process's output, as the Python helper's did.
var runCommand = func(argv []string, o runOptions) (runResult, error) {
	cmd := exec.Command(argv[0], argv[1:]...)
	var stdout, stderr bytes.Buffer
	if o.capture {
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
	} else {
		cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	}
	if o.input != "" {
		cmd.Stdin = strings.NewReader(o.input)
	}
	if o.env != nil {
		cmd.Env = o.env
	}
	err := cmd.Run()
	result := runResult{Stdout: stdout.String(), Stderr: stderr.String()}
	if err != nil {
		var exit *exec.ExitError
		if !errors.As(err, &exit) {
			return result, err
		}
		result.Code = exit.ExitCode()
		if o.check {
			return result, &CommandError{argv, result.Code, result.Stdout, result.Stderr}
		}
	}
	return result, nil
}

func run(argv []string, o runOptions) (runResult, error) { return runCommand(argv, o) }

// commandOutput is a command's standard output, "" when it cannot run.
func commandOutput(argv ...string) string {
	r, err := run(argv, runOptions{capture: true})
	if err != nil {
		return ""
	}
	return r.Stdout
}

var which = func(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

func sha256File(p string) (string, error) {
	f, err := os.Open(p)
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

func isHex64(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, c := range strings.ToLower(value) {
		if !strings.ContainsRune("0123456789abcdef", c) {
			return false
		}
	}
	return true
}

func formatBytes(value int64) string {
	size := float64(value)
	for _, suffix := range []string{"B", "KiB", "MiB", "GiB", "TiB"} {
		if size < 1024 || suffix == "TiB" {
			return fmt.Sprintf("%.1f %s", size, suffix)
		}
		size /= 1024
	}
	return fmt.Sprintf("%d B", value)
}

func requireRoot() error {
	if os.Geteuid() != 0 && os.Getenv("EASY_HA_PROXY_ALLOW_NON_ROOT") != "1" {
		return backupErrorf("Run as root (sudo).")
	}
	return nil
}
