package updateplan

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type localChange struct{ status, path string }

// statusEntries reads `git status --porcelain=v1 -z`; nil for staged
// changes, conflicts, renames, copies or unreadable entries. The worktree
// comparison cannot establish that index content is upstream, and resetting
// the checkout would discard that content too.
func statusEntries(stdout string) []localChange {
	entries := []localChange{}
	for _, item := range strings.Split(stdout, "\x00") {
		if item == "" {
			continue
		}
		if len(item) < 4 || item[2] != ' ' {
			return nil
		}
		status, path := item[:2], item[3:]
		okStatus := status == " M" || status == " D" || status == " T" || status == "??"
		escapes := false
		for _, part := range strings.Split(path, "/") {
			if part == ".." {
				escapes = true
			}
		}
		if !okStatus || path == "" || strings.HasPrefix(path, "/") || escapes {
			return nil
		}
		entries = append(entries, localChange{status, path})
	}
	return entries
}

// localChangesUpstream says whether every locally changed file already is
// what the candidate has. A fix tried by hand on a gateway and then
// committed leaves the checkout with exactly the files the next revision
// brings; replacing them loses nothing.
func localChangesUpstream(installed, candidate string, entries []localChange) bool {
	for _, e := range entries {
		here, there := filepath.Join(installed, e.path), filepath.Join(candidate, e.path)
		if isSymlink(here) || isSymlink(there) {
			a, errA := os.Readlink(here)
			b, errB := os.Readlink(there)
			if !(isSymlink(here) && isSymlink(there) && errA == nil && errB == nil && a == b) {
				return false
			}
			continue
		}
		if !exists(here) && !exists(there) {
			continue
		}
		if !(isFile(here) && isFile(there)) {
			return false
		}
		x, errX := os.ReadFile(here)
		y, errY := os.ReadFile(there)
		if errX != nil || errY != nil || !bytes.Equal(x, y) {
			return false
		}
	}
	return true
}

// gitCheckoutRevision returns the installed revision, or a blocking
// component. A component for local changes names the files and carries the
// entries (as _local_changes) so the plan can still see whether the next
// revision already holds those changes.
func gitCheckoutRevision(sourceDir, branch string, runner Runner) (string, M) {
	rev := runner.Run([]string{"git", "-C", sourceDir, "rev-parse", "HEAD"}, gitTimeout)
	if rev.Returncode != 0 {
		return "", component("all", "unknown", "The installed Git revision could not be read.", nil, nil,
			M{"reason": "git-revision-failed", "error": shortError(rev)})
	}
	local := revisionRe.FindString(strings.ToLower(rev.Stdout))
	if local == "" {
		return "", component("all", "unknown", "The installed Git revision was not valid.", nil, nil,
			M{"reason": "invalid-local-revision"})
	}
	// core.fileMode=false suppresses permission-only drift introduced by
	// controller-to-server source synchronization while retaining content and
	// untracked-file changes.
	status := runner.Run([]string{"git", "-C", sourceDir, "-c", "core.fileMode=false", "status", "--porcelain=v1", "-z",
		"--untracked-files=all"}, gitTimeout)
	if status.Returncode != 0 {
		return "", component("all", "unknown", "Local source changes could not be inspected.", local, nil,
			M{"reason": "git-status-failed", "error": shortError(status)})
	}
	var changes []string
	for _, item := range strings.Split(status.Stdout, "\x00") {
		if strings.TrimSpace(item) != "" {
			changes = append(changes, item)
		}
	}
	if len(changes) > 0 {
		files := []string{}
		for _, item := range changes {
			if len(item) > 3 {
				files = append(files, item[3:])
			} else {
				files = append(files, "")
			}
		}
		sort.Strings(files)
		if len(files) > maxChangedFiles {
			files = files[:maxChangedFiles]
		}
		c := component("all", "blocked", "The managed source has local content changes and will not be replaced automatically.",
			local, nil, M{"reason": "local-source-changes", "branch": branch, "changed_paths": len(changes),
				"changed_files": strList(files), "network_checked": false})
		if entries := statusEntries(status.Stdout); len(entries) > 0 {
			c["_local_changes"] = entries
		}
		return "", c
	}
	return local, nil
}

// recordedSourceRevision reads the marker written when the source tarball
// was packaged.
func recordedSourceRevision(sourceDir, branch string) (string, M) {
	marker := filepath.Join(sourceDir, sourceRevisionMarker)
	if !isFile(marker) {
		return "", component("all", "unknown", "The managed source is not a Git checkout and carries no recorded "+
			"revision, so its remote revision cannot be compared safely.", nil, nil, M{"reason": "not-a-git-checkout"})
	}
	raw, err := os.ReadFile(marker)
	if err != nil {
		return "", component("all", "unknown", "The recorded source revision could not be read.", nil, nil,
			M{"reason": "revision-marker-unreadable", "error": err.Error()})
	}
	fields := map[string]string{}
	for _, line := range strings.Split(string(raw), "\n") {
		if k, v, ok := strings.Cut(strings.TrimRight(line, "\r"), "="); ok {
			fields[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	revision := revisionRe.FindString(strings.ToLower(fields["revision"]))
	if revision == "" {
		return "", component("all", "unknown", "The recorded source revision is missing or invalid; reinstall or "+
			"re-synchronize the source to record it.", nil, nil, M{"reason": "invalid-recorded-revision"})
	}
	if strings.ToLower(strings.TrimSpace(fields["dirty"])) == "true" {
		return "", component("all", "blocked", "The source was synchronized from a working tree with uncommitted "+
			"changes, so it cannot be compared to the remote branch. Commit and push the changes, then re-synchronize.",
			revision, nil, M{"reason": "recorded-source-dirty", "branch": branch, "network_checked": false})
	}
	return revision, nil
}

func probeSource(sourceDir, channel, branch, repository string, runner Runner) M {
	if channel == "local" {
		return component("all", "blocked", "Git source checks are disabled for the local source channel.", nil, nil,
			M{"reason": "local-source-channel", "network_checked": false})
	}
	if !isDir(sourceDir) {
		return component("all", "blocked", "The managed source directory is missing.", nil, nil,
			M{"reason": "source-directory-missing"})
	}
	var local, origin string
	var dirty M
	if isDir(filepath.Join(sourceDir, ".git")) {
		local, dirty = gitCheckoutRevision(sourceDir, branch, runner)
		if dirty != nil {
			if _, ok := dirty["_local_changes"]; !ok {
				return dirty
			}
			// Whether the next revision already holds these changes is
			// decided once it has been fetched.
			local = str(dirty["current_version"])
		}
		o := runner.Run([]string{"git", "-C", sourceDir, "remote", "get-url", "origin"}, gitTimeout)
		origin = repository
		if o.Returncode == 0 {
			origin = strings.TrimSpace(o.Stdout)
		}
	} else {
		var marker M
		local, marker = recordedSourceRevision(sourceDir, branch)
		if marker != nil {
			return marker
		}
		origin = repository
	}
	if dirty != nil && badRef(origin) {
		delete(dirty, "_local_changes")
		return dirty
	}
	if badRef(origin) {
		return component("all", "unknown", "The source repository is not configured.", local, nil, M{"reason": "repository-missing"})
	}
	remote := runner.Run([]string{"git", "ls-remote", "--heads", "--", origin, "refs/heads/" + branch}, gitTimeout)
	remoteRevision := revisionRe.FindString(strings.ToLower(remote.Stdout))
	if dirty != nil && (remote.Returncode != 0 || remoteRevision == "") {
		// Without the next revision nothing can be compared: the local
		// changes stay the reason.
		delete(dirty, "_local_changes")
		return dirty
	}
	if remote.Returncode != 0 || remoteRevision == "" {
		return component("all", "unknown", "The remote source revision could not be checked.", local, nil,
			M{"reason": "remote-revision-unavailable", "branch": branch, "error": shortError(remote)})
	}
	if dirty != nil {
		if local == remoteRevision {
			delete(dirty, "_local_changes")
			return dirty
		}
		dirty["available_version"] = remoteRevision
		details(dirty)["network_checked"] = true
		return dirty
	}
	if local == remoteRevision {
		return component("all", "current", "The managed source is current.", local, remoteRevision, M{"branch": branch})
	}
	return component("all", "available", "A different remote managed source revision is available.", local, remoteRevision,
		M{"branch": branch})
}

// sourceOrigin is where the managed source comes from; "" when unusable. A
// tarball install has no checkout to read the origin from.
func sourceOrigin(sourceDir, repository string, runner Runner) string {
	origin := repository
	if isDir(filepath.Join(sourceDir, ".git")) {
		r := runner.Run([]string{"git", "-C", sourceDir, "remote", "get-url", "origin"}, gitTimeout)
		if r.Returncode == 0 {
			origin = strings.TrimSpace(r.Stdout)
		}
	}
	if badRef(origin) {
		return ""
	}
	return origin
}

// changelog: the commits an update brings, newest first; nil when unknown.
// Best effort: a missing changelog must never cost the plan.
func changelog(sourceDir, repository, branch, installed, candidate, destination string, runner Runner) (out M) {
	defer func() {
		if recover() != nil {
			out = nil
		}
	}()
	if !revisionFullRe.MatchString(installed) || !revisionFullRe.MatchString(candidate) {
		return nil
	}
	origin := sourceOrigin(sourceDir, repository, runner)
	if origin == "" {
		return nil
	}
	clone := runner.Run([]string{"git", "clone", "--quiet", "--bare", "--filter=tree:0", fmt.Sprintf("--depth=%d", changelogDepth),
		"--single-branch", "--branch", branch, "--", origin, destination}, cloneTimeout)
	if clone.Returncode != 0 {
		return nil
	}
	log := runner.Run([]string{"git", "-C", destination, "log", fmt.Sprintf("--max-count=%d", changelogDepth),
		"--format=%H%x1f%s", candidate}, gitTimeout)
	if log.Returncode != 0 {
		return nil
	}
	commits := []any{}
	complete := false
	for _, line := range strings.Split(log.Stdout, "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" {
			continue
		}
		revision, subject, _ := strings.Cut(line, "\x1f")
		revision = strings.ToLower(strings.TrimSpace(revision))
		if !revisionFullRe.MatchString(revision) {
			continue
		}
		if revision == installed {
			complete = true
			break
		}
		commits = append(commits, M{"revision": revision[:12],
			"subject": truncRunes(strings.TrimSpace(controlRe.ReplaceAllString(subject, "")), changelogSubjectChars)})
	}
	if len(commits) == 0 {
		return nil
	}
	shown := commits
	if len(shown) > changelogLimit {
		shown = shown[:changelogLimit]
	}
	// complete false: the installed revision is further back than the
	// history read, so there are at least this many.
	return M{"count": len(commits), "complete": complete, "commits": shown}
}

// borrowedCandidate fetches the candidate into a scratch repository that
// borrows the installed objects; "" when it is checked out at destination.
// The installed checkout already holds almost every file of the next
// revision, and Git sends only what the receiver lacks when it can say what
// it has. The installed checkout is only read -- its objects are listed as
// an alternate and its shallow boundary copied -- so a check never moves
// what is installed.
func borrowedCandidate(sourceDir, origin, branch, destination string, runner Runner) string {
	objects := filepath.Join(sourceDir, ".git", "objects")
	if !isDir(objects) {
		return "no-installed-objects"
	}
	objectsPath, err := filepath.Abs(objects)
	if err == nil {
		if resolved, err := filepath.EvalSymlinks(objectsPath); err == nil {
			objectsPath = resolved
		}
	}
	if strings.ContainsAny(objectsPath, "\r\n\x00") {
		return "installed-objects-unusable"
	}
	if init := runner.Run([]string{"git", "init", "--quiet", "--", destination}, gitTimeout); init.Returncode != 0 {
		return "candidate-init-failed: " + shortError(init)
	}
	gitDir := filepath.Join(destination, ".git")
	info := filepath.Join(gitDir, "objects", "info")
	if err := os.MkdirAll(info, 0o755); err != nil {
		return truncRunes(fmt.Sprintf("candidate-scratch-failed: %v", err), 200)
	}
	if err := os.WriteFile(filepath.Join(info, "alternates"), []byte(objectsPath+"\n"), 0o644); err != nil {
		return truncRunes(fmt.Sprintf("candidate-scratch-failed: %v", err), 200)
	}
	if shallow := filepath.Join(sourceDir, ".git", "shallow"); isFile(shallow) {
		// Without the boundary Git walks past the installed commit to
		// parents the shallow checkout never had, and gives up.
		raw, err := os.ReadFile(shallow)
		if err == nil {
			err = os.WriteFile(filepath.Join(gitDir, "shallow"), raw, 0o644)
		}
		if err != nil {
			return truncRunes(fmt.Sprintf("candidate-scratch-failed: %v", err), 200)
		}
	}
	fetch := runner.Run([]string{"git", "-C", destination, "fetch", "--quiet", "--depth=1", "--no-tags", "--", origin,
		"refs/heads/" + branch}, candidateTimeout)
	if fetch.Returncode != 0 {
		if fetch.Error == "timeout" {
			return "candidate-fetch-timed-out: " + shortError(fetch)
		}
		return "candidate-fetch-failed: " + shortError(fetch)
	}
	checkout := runner.Run([]string{"git", "-C", destination, "checkout", "--quiet", "--detach", "FETCH_HEAD"}, gitTimeout)
	if checkout.Returncode != 0 {
		return "candidate-checkout-failed: " + shortError(checkout)
	}
	return ""
}

// remoteCandidate checks the candidate revision out at destination.
func remoteCandidate(sourceDir, repository, branch, expected, destination string, runner Runner) (string, string) {
	origin := sourceOrigin(sourceDir, repository, runner)
	if origin == "" {
		return "", "repository-missing"
	}
	borrowed := borrowedCandidate(sourceDir, origin, branch, destination, runner)
	if strings.HasPrefix(borrowed, "candidate-fetch-timed-out") {
		// A full clone moves more than the fetch that just ran out of time.
		return "", borrowed
	}
	if borrowed != "" {
		os.RemoveAll(destination)
		clone := runner.Run([]string{"git", "clone", "--quiet", "--depth=1", "--single-branch", "--branch", branch, "--", origin,
			destination}, candidateTimeout)
		if clone.Returncode != 0 {
			reason := "failed"
			if clone.Error == "timeout" {
				reason = "timed-out"
			}
			return "", "candidate-clone-" + reason + ": " + shortError(clone)
		}
	}
	rev := runner.Run([]string{"git", "-C", destination, "rev-parse", "HEAD"}, gitTimeout)
	revision := revisionRe.FindString(strings.ToLower(rev.Stdout))
	if rev.Returncode != 0 || revision == "" {
		return "", "candidate-revision-unavailable"
	}
	if revision != expected {
		return "", "candidate-revision-changed-during-check"
	}
	return destination, ""
}

// goWebTreeInputs are the web application's build inputs: CI and the update
// broker fingerprint the same paths.
var goWebTreeInputs = []string{"VERSION", "go/panel"}

// webTree is the web application's build-input fingerprint for a Git
// source tree: the sha256 of `git ls-tree` over its inputs, as CI labels the
// image it builds. Unknown ("") is an answer the pairing rules handle.
func webTree(root string, runner Runner) (tree string) {
	defer func() {
		if recover() != nil {
			tree = ""
		}
	}()
	if !exists(filepath.Join(root, ".git")) {
		return ""
	}
	argv := append([]string{"git", "-C", root, "ls-tree", "-r", "--full-tree", "HEAD", "--"}, goWebTreeInputs...)
	r := runner.Run(argv, gitTimeout)
	if r.Returncode != 0 || strings.TrimSpace(r.Stdout) == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(r.Stdout))
	return hex.EncodeToString(sum[:])
}
