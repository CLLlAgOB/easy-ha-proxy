package authelia

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"errors"
	"fmt"
	"log"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/pyyaml"
)

func randRead(b []byte) (int, error) { return rand.Read(b) }

func (c *Configd) dockerIn(dir string, timeout time.Duration, args ...string) (int, string, string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, c.Opts.DockerBin, args...)
	cmd.Dir = dir
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	if ctx.Err() == context.DeadlineExceeded {
		return 0, "", "", newErr("TimeoutExpired", "Command '%s' timed out after %d seconds", pyArgv(append([]string{"docker"}, args...)), int(timeout.Seconds()))
	}
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return ee.ExitCode(), out.String(), errb.String(), nil
		}
		return 0, "", "", newErr("FileNotFoundError", "[Errno 2] No such file or directory: 'docker'")
	}
	return 0, out.String(), errb.String(), nil
}

var (
	notificationIDRE    = regexp.MustCompile(`^[a-f0-9]{64}$`)
	notificationActorRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.@+-]{0,127}$`)
	notifyBasenameRE    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	recipientMaskRE     = regexp.MustCompile("([A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+)@([A-Za-z0-9.-]+)")
)

func inboxErr(format string, args ...any) error {
	return newErr("NotificationInboxError", format, args...)
}
func inboxConflict(format string, args ...any) error {
	return newErr("NotificationInboxConflict", format, args...)
}

func (c *Configd) notificationSourcePath(config *pyyaml.Map) (string, error) {
	notifier := asMap(config.Value("notifier"))
	var fs *pyyaml.Map
	if notifier != nil {
		fs = asMap(notifier.Value("filesystem"))
	}
	if fs == nil {
		return "", inboxErr("filesystem notifications are not enabled")
	}
	filename, ok := fs.Value("filename").(string)
	if !ok {
		return "", inboxErr("filesystem notification filename is invalid")
	}
	parts := strings.Split(pyStrip(filename), "/")
	base := ""
	if len(parts) == 3 && parts[0] == "" && parts[1] == "config" {
		base = parts[2]
	}
	if !notifyBasenameRE.MatchString(base) {
		return "", inboxErr("filesystem notification filename must be a direct /config file")
	}
	var st syscall.Stat_t
	if err := syscall.Lstat(c.Opts.NotificationRootDir, &st); err != nil {
		return "", inboxErr("the local notification root is unavailable")
	}
	if st.Mode&syscall.S_IFMT != syscall.S_IFDIR {
		return "", inboxErr("the local notification root is unsafe")
	}
	if st.Mode&0o022 != 0 {
		return "", inboxErr("the local notification root is writable by peers")
	}
	if c.Opts.NotificationExpectedUID >= 0 && int(st.Uid) != c.Opts.NotificationExpectedUID {
		return "", inboxErr("the local notification root owner is invalid")
	}
	return filepath.Join(c.Opts.NotificationRootDir, base), nil
}

type notifySnapshot struct {
	data                                      []byte
	id, receivedAt, revision, sourceKey, text string
}

// openNotificationSnapshot is _open_notification_snapshot; nil when there
// is no current notification.
func (c *Configd) openNotificationSnapshot(config *pyyaml.Map) (*notifySnapshot, error) {
	path, err := c.notificationSourcePath(config)
	if err != nil {
		return nil, err
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		if err == syscall.ENOENT {
			return nil, nil
		}
		return nil, inboxErr("the local notification cannot be opened safely")
	}
	defer syscall.Close(fd)
	var before syscall.Stat_t
	if err := syscall.Fstat(fd, &before); err != nil {
		return nil, err
	}
	switch {
	case before.Mode&syscall.S_IFMT != syscall.S_IFREG:
		return nil, inboxErr("the local notification is not a regular file")
	case before.Mode&0o7777 != 0o600:
		return nil, inboxErr("the local notification permissions are unsafe")
	case before.Nlink != 1:
		return nil, inboxErr("the local notification has an unsafe link count")
	case c.Opts.NotificationExpectedUID >= 0 && int(before.Uid) != c.Opts.NotificationExpectedUID:
		return nil, inboxErr("the local notification owner is invalid")
	case before.Size < 0 || before.Size > notificationMaxBytes:
		return nil, inboxErr("the local notification is too large")
	}
	data := []byte{}
	buf := make([]byte, 65536)
	for len(data) <= notificationMaxBytes {
		n, err := syscall.Read(fd, buf)
		if err != nil {
			if err == syscall.EINTR {
				continue
			}
			return nil, err
		}
		if n <= 0 {
			break
		}
		data = append(data, buf[:n]...)
	}
	var after syscall.Stat_t
	if err := syscall.Fstat(fd, &after); err != nil {
		return nil, err
	}
	mtimeNS := func(st *syscall.Stat_t) int64 { return st.Mtim.Sec*1e9 + st.Mtim.Nsec }
	if before.Dev != after.Dev || before.Ino != after.Ino || before.Size != after.Size || mtimeNS(&before) != mtimeNS(&after) {
		return nil, inboxConflict("the local notification changed while it was being read")
	}
	if len(data) > notificationMaxBytes {
		return nil, inboxErr("the local notification is too large")
	}
	if len(bytes.Trim(data, asciiSpace)) == 0 {
		return nil, nil
	}
	if utf8Error(data) != nil {
		return nil, inboxErr("the local notification is not valid UTF-8")
	}
	identity := fmt.Sprintf("(%d, %d, %d, %d)", after.Dev, after.Ino, after.Size, mtimeNS(&after))
	sourceKey := hmacHex(c.notifyRevisionKey, []byte("easy-ha-proxy-notification-source-v1\x00"), []byte(identity), []byte{0}, data)
	id := hmacHex(c.notifyRevisionKey, []byte("easy-ha-proxy-notification-id-v1\x00"+sourceKey))
	revision := hmacHex(c.notifyRevisionKey, []byte("easy-ha-proxy-notification-revision-v1\x00"+sourceKey))
	mtime := float64(after.Mtim.Sec) + float64(after.Mtim.Nsec)/1e9
	return &notifySnapshot{data: data, id: id, receivedAt: isoUTC(mtime), revision: revision, sourceKey: sourceKey,
		text: string(data)}, nil
}

// isoUTC is datetime.fromtimestamp(ts, tz=timezone.utc).isoformat().
func isoUTC(ts float64) string {
	sec, frac := math.Modf(ts)
	t := time.Unix(int64(sec), int64(math.Round(frac*1e6))*1000).UTC()
	if t.Nanosecond() == 0 {
		return t.Format("2006-01-02T15:04:05") + "+00:00"
	}
	return t.Format("2006-01-02T15:04:05.000000") + "+00:00"
}

func (c *Configd) notificationStatePath() string {
	if c.Opts.NotificationStateFile != "" {
		return c.Opts.NotificationStateFile
	}
	return filepath.Join(c.Opts.NotificationStateDir, "authelia-notification-state.json")
}

func (c *Configd) notificationStateDirectory(path string) (string, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", inboxErr("the local notification state directory is unavailable")
	}
	var st syscall.Stat_t
	if err := syscall.Lstat(dir, &st); err != nil {
		return "", inboxErr("the local notification state directory is unavailable")
	}
	if st.Mode&syscall.S_IFMT != syscall.S_IFDIR {
		return "", inboxErr("the local notification state directory is unsafe")
	}
	if int(st.Uid) != os.Geteuid() || st.Mode&0o077 != 0 {
		return "", inboxErr("the local notification state directory is not root-only")
	}
	return dir, nil
}

var notificationStateKeys = []string{"actor", "handled", "handled_at", "id", "revision", "source_key", "version"}

func (c *Configd) loadNotificationState() (*pyyaml.Map, error) {
	path := c.notificationStatePath()
	if _, err := os.Lstat(path); err != nil {
		return pyyaml.NewMap(), nil
	}
	raw, st, err := safeReadFile(path)
	if err != nil {
		return nil, inboxErr("the local notification state is invalid")
	}
	if int(st.Uid) != os.Geteuid() {
		return nil, inboxErr("the local notification state owner is invalid")
	}
	if st.Mode&0o7777 != 0o600 {
		return nil, inboxErr("the local notification state permissions are unsafe")
	}
	if st.Nlink != 1 || st.Size > notificationStateMax {
		return nil, inboxErr("the local notification state is unsafe")
	}
	if utf8Error(raw) != nil {
		return nil, inboxErr("the local notification state is invalid")
	}
	v, err := pyyaml.JSONLoads(raw)
	if err != nil {
		return nil, inboxErr("the local notification state is invalid")
	}
	state, ok := v.(*pyyaml.Map)
	if !ok {
		return nil, inboxErr("the local notification state is invalid")
	}
	if state.Len() == 0 {
		return state, nil
	}
	str := func(k string) (string, bool) { s, ok := state.Value(k).(string); return s, ok }
	valid := state.Len() == len(notificationStateKeys) && sameKeys(state, notificationStateKeys...)
	if n, ok := state.Value("version").(int64); !ok || n != 1 {
		valid = false
	}
	if state.Value("handled") != true {
		valid = false
	}
	for _, k := range []string{"id", "revision", "source_key"} {
		if s, ok := str(k); !ok || !notificationIDRE.MatchString(s) {
			valid = false
		}
	}
	if s, ok := str("actor"); !ok || !notificationActorRE.MatchString(s) {
		valid = false
	}
	if s, ok := str("handled_at"); !ok || utf8.RuneCountInString(s) > 64 || controlRE.MatchString(s) {
		valid = false
	}
	if !valid {
		return nil, inboxErr("the local notification state is invalid")
	}
	return state, nil
}

func (c *Configd) writeNotificationState(state *pyyaml.Map) error {
	path := c.notificationStatePath()
	dir, err := c.notificationStateDirectory(path)
	if err != nil {
		return err
	}
	var cur syscall.Stat_t
	if err := syscall.Lstat(path, &cur); err == nil {
		if cur.Mode&syscall.S_IFMT != syscall.S_IFREG || int(cur.Uid) != os.Geteuid() || cur.Mode&0o7777 != 0o600 || cur.Nlink != 1 {
			return inboxErr("the local notification state path is unsafe")
		}
	}
	text, err := pyyaml.JSONDumps(state.Sorted(), false, true)
	if err != nil {
		return err
	}
	payload := []byte(text + "\n")
	if len(payload) > notificationStateMax {
		return inboxErr("the local notification state is too large")
	}
	tmp, err := os.CreateTemp(dir, ".authelia-notification-latest.*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	keep := false
	defer func() {
		if !keep {
			_ = os.Remove(name)
		}
	}()
	_ = tmp.Chmod(0o600)
	if _, err := tmp.Write(payload); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	tmp.Close()
	if err := os.Rename(name, path); err != nil {
		return err
	}
	keep = true
	fsyncDirectories([]string{path})
	return nil
}

type notifyState struct {
	id, revision string
	handled      bool
	handledAt    any
}

func (c *Configd) notificationStateFor(s *notifySnapshot) (notifyState, error) {
	tomb, err := c.loadNotificationState()
	if err != nil {
		return notifyState{}, err
	}
	eq := func(k, v string) bool { t, _ := tomb.Value(k).(string); return hmac.Equal([]byte(t), []byte(v)) }
	handled := tomb.Len() > 0 && eq("source_key", s.sourceKey) && eq("id", s.id) && eq("revision", s.revision)
	st := notifyState{id: s.id, revision: s.revision, handled: handled}
	if handled {
		st.handledAt = tomb.Value("handled_at")
	}
	return st, nil
}

func notificationHeader(text string, names map[string]bool, maximum int) string {
	lines := splitLines(text)
	if len(lines) > 20 {
		lines = lines[:20]
	}
	for _, line := range lines {
		if pyStrip(line) == "" {
			break
		}
		key, value, found := strings.Cut(line, ":")
		if found && names[strings.ToLower(pyStrip(key))] {
			cleaned := strings.Join(strings.Fields(pyStrip(value)), " ")
			if r := []rune(cleaned); len(r) > maximum {
				cleaned = string(r[:maximum])
			}
			return cleaned
		}
	}
	return ""
}

func maskNotificationRecipient(value string) string {
	m := recipientMaskRE.FindStringSubmatch(value)
	if m == nil {
		if value != "" {
			return "••••"
		}
		return ""
	}
	visible := "•"
	if m[1] != "" {
		r, _ := utf8.DecodeRuneInString(m[1])
		visible = string(r)
	}
	return visible + "***@" + strings.ToLower(m[2])
}

func notificationMetadata(s *notifySnapshot, st notifyState) map[string]any {
	recipient := notificationHeader(s.text, map[string]bool{"recipient": true, "to": true}, 320)
	return map[string]any{"id": st.id, "revision": st.revision, "received_at": s.receivedAt,
		"recipient_masked": maskNotificationRecipient(recipient), "size": len(s.data), "handled": st.handled,
		"handled_at": st.handledAt}
}

func (c *Configd) notificationLatest() (map[string]any, error) {
	config, _, err := c.loadConfigData()
	if err != nil {
		return nil, err
	}
	if mailMode(config) != "filesystem" {
		return map[string]any{"ok": true, "mode": "relay", "status": "disabled", "latest": nil}, nil
	}
	s, err := c.openNotificationSnapshot(config)
	if err != nil {
		return nil, err
	}
	if s == nil {
		return map[string]any{"ok": true, "mode": "filesystem", "status": "empty", "latest": nil}, nil
	}
	st, err := c.notificationStateFor(s)
	if err != nil {
		return nil, err
	}
	status := "pending"
	if st.handled {
		status = "handled"
	}
	return map[string]any{"ok": true, "mode": "filesystem", "status": status, "latest": notificationMetadata(s, st)}, nil
}

func validateNotificationReference(req *pyyaml.Map) (string, string, error) {
	id, ok1 := req.Value("id").(string)
	rev, ok2 := req.Value("revision").(string)
	if !ok1 || !notificationIDRE.MatchString(id) || !ok2 || !notificationIDRE.MatchString(rev) {
		return "", "", newErr("ValueError", "id and revision must be current 64-character values")
	}
	return id, rev, nil
}

func validateNotificationActor(v any) (string, error) {
	s, ok := v.(string)
	if !ok {
		return "", newErr("ValueError", "actor is required")
	}
	actor := pyStrip(s)
	if !notificationActorRE.MatchString(actor) {
		return "", newErr("ValueError", "actor is invalid")
	}
	return actor, nil
}

func (c *Configd) requireCurrentNotification(config *pyyaml.Map, id, rev string) (*notifySnapshot, notifyState, error) {
	if mailMode(config) != "filesystem" {
		return nil, notifyState{}, inboxConflict("filesystem notifications are not enabled")
	}
	s, err := c.openNotificationSnapshot(config)
	if err != nil {
		return nil, notifyState{}, err
	}
	if s == nil {
		return nil, notifyState{}, inboxConflict("there is no current local notification")
	}
	st, err := c.notificationStateFor(s)
	if err != nil {
		return nil, notifyState{}, err
	}
	if !hmac.Equal([]byte(st.id), []byte(id)) || !hmac.Equal([]byte(st.revision), []byte(rev)) {
		return nil, notifyState{}, inboxConflict("the local notification changed; refresh before continuing")
	}
	return s, st, nil
}

func (c *Configd) claimNotificationReveal(actor string) int {
	c.revealMu.Lock()
	defer c.revealMu.Unlock()
	now := time.Now()
	cooldown := float64(c.Opts.NotificationRevealCooldown)
	if prev, ok := c.revealedAt[actor]; ok {
		remaining := cooldown - now.Sub(prev).Seconds()
		if remaining > 0 {
			r := int(remaining + 0.999)
			if r < 1 {
				r = 1
			}
			return r
		}
	}
	c.revealedAt[actor] = now
	keep := math.Max(300, cooldown*10)
	for a, t := range c.revealedAt {
		if now.Sub(t).Seconds() > keep {
			delete(c.revealedAt, a)
		}
	}
	return 0
}

func notifyFailure(err error, generic string) map[string]any {
	if errKind(err) == "NotificationInboxConflict" {
		return map[string]any{"ok": false, "conflict": true, "error": errText(err)}
	}
	return map[string]any{"ok": false, "error": generic}
}

func (c *Configd) handleNotificationLatest(req *pyyaml.Map) map[string]any {
	if !sameKeys(req, "action") {
		return map[string]any{"ok": false, "validation_error": true, "error": "notification_latest does not accept additional fields"}
	}
	unlock, err := c.mailLock()
	if err != nil {
		return notifyFailure(err, "failed to read local notification metadata")
	}
	defer unlock()
	r, err := c.notificationLatest()
	if err != nil {
		log.Printf("Failed to read local Authelia notification metadata")
		return notifyFailure(err, "failed to read local notification metadata")
	}
	return r
}

func (c *Configd) handleNotificationReveal(req *pyyaml.Map) map[string]any {
	if !sameKeys(req, "action", "id", "revision", "actor") {
		return map[string]any{"ok": false, "validation_error": true, "error": "id, revision, and actor are required"}
	}
	id, rev, err := validateNotificationReference(req)
	if err == nil {
		_, err = validateNotificationActor(req.Value("actor"))
	}
	if err != nil {
		return map[string]any{"ok": false, "validation_error": true, "error": errText(err)}
	}
	actor, _ := validateNotificationActor(req.Value("actor"))
	unlock, err := c.mailLock()
	if err != nil {
		return notifyFailure(err, "failed to reveal local notification")
	}
	defer unlock()
	config, _, err := c.loadConfigData()
	if err != nil {
		return notifyFailure(err, "failed to reveal local notification")
	}
	s, st, err := c.requireCurrentNotification(config, id, rev)
	if err != nil {
		log.Printf("Failed to reveal local Authelia notification")
		return notifyFailure(err, "failed to reveal local notification")
	}
	if retry := c.claimNotificationReveal(actor); retry > 0 {
		return map[string]any{"ok": false, "rate_limited": true, "retry_after": retry,
			"error": "please wait before revealing the notification again"}
	}
	log.Printf("Local Authelia notification revealed by actor=%s", pyRepr(actor))
	return map[string]any{"ok": true, "id": st.id, "revision": st.revision, "content": s.text}
}

func (c *Configd) handleNotificationHandle(req *pyyaml.Map) map[string]any {
	if !sameKeys(req, "action", "id", "revision", "handled", "actor") {
		return map[string]any{"ok": false, "validation_error": true, "error": "id, revision, handled=true, and actor are required"}
	}
	if req.Value("handled") != true {
		return map[string]any{"ok": false, "validation_error": true, "error": "handled must be true"}
	}
	id, rev, err := validateNotificationReference(req)
	var actor string
	if err == nil {
		actor, err = validateNotificationActor(req.Value("actor"))
	}
	if err != nil {
		return map[string]any{"ok": false, "validation_error": true, "error": errText(err)}
	}
	unlock, err := c.mailLock()
	if err != nil {
		return notifyFailure(err, "failed to update local notification status")
	}
	defer unlock()
	config, _, err := c.loadConfigData()
	if err != nil {
		return notifyFailure(err, "failed to update local notification status")
	}
	s, _, err := c.requireCurrentNotification(config, id, rev)
	if err != nil {
		log.Printf("Failed to update local Authelia notification status")
		return notifyFailure(err, "failed to update local notification status")
	}
	handledAt := isoUTC(float64(time.Now().UnixNano()) / 1e9)
	state := pyyaml.NewMap()
	for _, p := range []struct {
		k string
		v any
	}{{"version", int64(1)}, {"source_key", s.sourceKey}, {"id", s.id}, {"revision", s.revision}, {"handled", true},
		{"handled_at", handledAt}, {"actor", actor}} {
		state.Set(p.k, p.v)
	}
	if err := c.writeNotificationState(state); err != nil {
		log.Printf("Failed to update local Authelia notification status")
		return notifyFailure(err, "failed to update local notification status")
	}
	log.Printf("Local Authelia notification marked handled by actor=%s", pyRepr(actor))
	return map[string]any{"ok": true, "status": "handled",
		"latest": notificationMetadata(s, notifyState{id: s.id, revision: s.revision, handled: true, handledAt: handledAt})}
}

const asciiSpace = " \t\n\r\v\f"
