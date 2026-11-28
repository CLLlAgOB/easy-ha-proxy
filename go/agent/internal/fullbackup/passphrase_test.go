package fullbackup

import (
	"bytes"
	"io"
	"path/filepath"
	"strings"
	"testing"
)

type typing struct {
	answers []string
	asked   int
}

// typed makes the terminal answer these, in order.
func typed(t *testing.T, answers ...string) *typing {
	t.Helper()
	tp := &typing{answers: answers}
	swap(t, &term.getpass, func(string) (string, error) {
		if tp.asked >= len(tp.answers) {
			t.Fatal("asked once too often")
		}
		tp.asked++
		return tp.answers[tp.asked-1], nil
	})
	return tp
}

func atATerminal(t *testing.T, yes bool) *bytes.Buffer {
	t.Helper()
	swap(t, &term.isTTY, func() bool { return yes })
	errors := &bytes.Buffer{}
	swap(t, &term.stderr, io.Writer(errors))
	return errors
}

func TestThePassphraseFromStdinIsOneLine(t *testing.T) {
	t.Setenv("EASY_HA_PROXY_ALLOW_NON_ROOT", "1")
	t.Setenv("EASY_HA_PROXY_TEST_PASSPHRASE", "environment passphrase")
	withStdin(t, passphrase+"  \nunused second line\n")
	swap(t, &term.getpass, func(string) (string, error) { t.Fatal("getpass must not be used"); return "", nil })
	got, err := readPassphrase(true, true)
	if err != nil || got != passphrase+"  " {
		t.Fatalf("%q %v", got, err)
	}
	if rest, _ := term.stdin.ReadString('\n'); rest != "unused second line\n" {
		t.Fatalf("read more than one line: %q", rest)
	}
	withStdin(t, "short\n")
	if _, err := readPassphrase(false, true); err == nil {
		t.Fatal("a short piped passphrase was accepted")
	}
	withStdin(t, "")
	if _, err := readPassphrase(false, true); err == nil || !strings.Contains(err.Error(), "No backup passphrase") {
		t.Fatalf("empty stdin: %v", err)
	}
}

func TestATypedPassphraseIsConfirmed(t *testing.T) {
	atATerminal(t, true)
	tp := typed(t, passphrase, passphrase)
	if got, err := readPassphrase(true, false); err != nil || got != passphrase || tp.asked != 2 {
		t.Fatalf("%q %v asked %d", got, err, tp.asked)
	}
}

func TestAShortOneIsAskedForAgain(t *testing.T) {
	errors := atATerminal(t, true)
	tp := typed(t, "short", "stillshort", passphrase)
	if got, err := readPassphrase(false, false); err != nil || got != passphrase || tp.asked != 3 {
		t.Fatalf("%q %v asked %d", got, err, tp.asked)
	}
	if !strings.Contains(errors.String(), "at least 12 characters") || !strings.Contains(errors.String(), "Try again") {
		t.Fatalf("stderr %q", errors.String())
	}
}

func TestAMismatchStartsOver(t *testing.T) {
	errors := atATerminal(t, true)
	tp := typed(t, passphrase, "something else!!", passphrase, passphrase)
	if got, err := readPassphrase(true, false); err != nil || got != passphrase || tp.asked != 4 {
		t.Fatalf("%q %v asked %d", got, err, tp.asked)
	}
	if !strings.Contains(errors.String(), "do not match") {
		t.Fatalf("stderr %q", errors.String())
	}
}

func TestWithoutATerminalItFailsOnce(t *testing.T) {
	atATerminal(t, false)
	tp := typed(t, "short", passphrase)
	if _, err := readPassphrase(false, false); err == nil || tp.asked != 1 {
		t.Fatalf("err %v asked %d", err, tp.asked)
	}
}

func TestWhoCountsAsTyping(t *testing.T) {
	atATerminal(t, true)
	if !passphraseIsTyped(false) || passphraseIsTyped(true) {
		t.Fatal("a terminal")
	}
	t.Setenv("EASY_HA_PROXY_TEST_PASSPHRASE", passphrase)
	t.Setenv("EASY_HA_PROXY_ALLOW_NON_ROOT", "1")
	if !passphraseIsTyped(false) {
		t.Fatal("environment variables disabled terminal passphrase input")
	}
	swap(t, &term.isTTY, func() bool { return false })
	if passphraseIsTyped(false) {
		t.Fatal("no terminal")
	}
}

type outcome struct {
	opened *openedArchive
	err    error
}

func openWith(t *testing.T, outcomes []outcome, terminal bool, answers ...string) (*openedArchive, *typing, *bytes.Buffer, string, error) {
	t.Helper()
	work := t.TempDir()
	errors := atATerminal(t, terminal)
	tp := typed(t, answers...)
	swap(t, &validateBackupArchive, func(_, _, work string, _, _ bool) (*openedArchive, error) {
		next := outcomes[0]
		outcomes = outcomes[1:]
		if next.err != nil {
			writeText(t, filepath.Join(work, "bundle.tar.gz"), "half decrypted")
			return nil, next.err
		}
		return next.opened, nil
	})
	opened, err := openBackupArchive(filepath.Join(work, "backup.tar.gz.enc"), work, false, false)
	return opened, tp, errors, work, err
}

func TestAWrongPassphraseIsAskedForAgain(t *testing.T) {
	want := &openedArchive{manifest: map[string]any{"format": "x"}}
	opened, tp, errors, work, err := openWith(t, []outcome{{err: wrongPassphrase()}, {opened: want}}, true, "wrong passphrase!", passphrase)
	if err != nil || opened != want || tp.asked != 2 || !strings.Contains(errors.String(), "does not open this backup") {
		t.Fatalf("opened %v err %v asked %d stderr %q", opened, err, tp.asked, errors.String())
	}
	// The failed attempt left nothing for the next one to trip on.
	if lexists(filepath.Join(work, "bundle.tar.gz")) {
		t.Fatal("the half-decrypted bundle stayed")
	}
}

func TestWithoutATerminalAWrongPassphraseEndsIt(t *testing.T) {
	if _, _, _, _, err := openWith(t, []outcome{{err: wrongPassphrase()}}, false, passphrase); !isWrongPassphrase(err) {
		t.Fatalf("err %v", err)
	}
}

func TestAnyOtherFaultIsNotRetried(t *testing.T) {
	_, tp, _, _, err := openWith(t, []outcome{{err: backupErrorf("Full-backup manifest is missing")}}, true, passphrase)
	if err == nil || isWrongPassphrase(err) || tp.asked != 1 {
		t.Fatalf("err %v asked %d", err, tp.asked)
	}
}
