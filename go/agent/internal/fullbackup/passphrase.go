package fullbackup

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

// console is where passphrases and confirmations are read; the tests
// replace it.
type console struct {
	stdin  *bufio.Reader
	stderr io.Writer
	// isTTY says whether a person is typing at standard input.
	isTTY func() bool
	// getpass prompts without echo, on the terminal when there is one.
	getpass func(prompt string) (string, error)
}

var term = &console{
	stdin:  bufio.NewReader(os.Stdin),
	stderr: os.Stderr,
	isTTY: func() bool {
		_, err := unix.IoctlGetTermios(int(os.Stdin.Fd()), unix.TCGETS)
		return err == nil
	},
}

func init() { term.getpass = terminalGetpass }

// terminalGetpass is Python's getpass.getpass: the prompt and the answer on
// /dev/tty with echo off, standard input when there is no terminal.
func terminalGetpass(prompt string) (string, error) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		fmt.Fprint(os.Stderr, prompt)
		return readLine(term.stdin)
	}
	defer tty.Close()
	fd := int(tty.Fd())
	old, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	if err != nil {
		fmt.Fprint(os.Stderr, prompt)
		return readLine(term.stdin)
	}
	quiet := *old
	quiet.Lflag &^= unix.ECHO
	quiet.Lflag |= unix.ICANON
	if err := unix.IoctlSetTermios(fd, unix.TCSETS, &quiet); err != nil {
		return "", err
	}
	defer func() {
		_ = unix.IoctlSetTermios(fd, unix.TCSETS, old)
		fmt.Fprint(tty, "\n")
	}()
	fmt.Fprint(tty, prompt)
	return readLine(bufio.NewReader(tty))
}

// readLine is one line without its end; io.EOF when there was none.
func readLine(r *bufio.Reader) (string, error) {
	line, err := r.ReadString('\n')
	if err != nil && line == "" {
		return "", io.EOF
	}
	return strings.TrimRight(line, "\r\n"), nil
}

// input is Python's input(): the prompt on standard output, one line back.
func input(prompt string) string {
	fmt.Print(prompt)
	line, err := readLine(term.stdin)
	if err != nil {
		return ""
	}
	return line
}

func testPassphrase() (string, bool) {
	value, set := os.LookupEnv("EASY_HA_PROXY_TEST_PASSPHRASE")
	return value, set && os.Getenv("EASY_HA_PROXY_ALLOW_NON_ROOT") == "1"
}

// passphraseIsTyped says whether a person is at a terminal typing the
// passphrase: only then is asking again any use. A piped passphrase is the
// same on every attempt, so a second try would only repeat the failure.
func passphraseIsTyped(fromStdin bool) bool {
	if fromStdin {
		return false
	}
	if _, testing := testPassphrase(); testing {
		return false
	}
	return term.isTTY()
}

// readPassphrase: one line from standard input, the test passphrase, or a
// prompt that asks again until it gets a usable answer (Ctrl+C stops it).
var readPassphrase = func(confirm, fromStdin bool) (string, error) {
	if fromStdin {
		line, err := term.stdin.ReadString('\n')
		if err != nil && line == "" {
			return "", backupErrorf("No backup passphrase was supplied on stdin.")
		}
		first := strings.TrimRight(line, "\r\n")
		if len([]rune(first)) < 12 {
			return "", backupErrorf("Use a backup passphrase of at least 12 characters.")
		}
		return first, nil
	}
	if value, testing := testPassphrase(); testing {
		return value, nil
	}
	retry := passphraseIsTyped(fromStdin)
	for {
		if err := checkInterrupt(); err != nil {
			return "", err
		}
		first, err := term.getpass("Backup passphrase: ")
		if err != nil {
			return "", backupErrorf("No backup passphrase was supplied.")
		}
		problem := ""
		if len([]rune(first)) < 12 {
			problem = "Use a backup passphrase of at least 12 characters."
		} else if confirm {
			second, err := term.getpass("Repeat backup passphrase: ")
			if err != nil || first != second {
				problem = "Backup passphrases do not match."
			}
		}
		if problem == "" {
			return first, nil
		}
		if !retry {
			return "", backupErrorf("%s", problem)
		}
		fmt.Fprintf(term.stderr, "%s Try again, or press Ctrl+C to stop.\n", problem)
	}
}
