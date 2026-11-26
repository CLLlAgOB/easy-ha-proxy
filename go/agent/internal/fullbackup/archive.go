package fullbackup

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

func isRegularMember(h *tar.Header) bool {
	switch h.Typeflag {
	case tar.TypeReg, tar.TypeRegA, tar.TypeCont, tar.TypeGNUSparse:
		return true
	}
	return false
}

// validateBundleMember refuses absolute or escaping names, special files and
// links that leave the archive.
func validateBundleMember(h *tar.Header) error {
	if strings.HasPrefix(h.Name, "/") || hasDotDot(h.Name) {
		return backupErrorf("Unsafe bundle entry: %s", h.Name)
	}
	normalized := pyNormpath(h.Name)
	if normalized == "" || normalized == "." {
		return backupErrorf("Unsafe bundle entry: %s", h.Name)
	}
	isLink := h.Typeflag == tar.TypeSymlink || h.Typeflag == tar.TypeLink
	if !(isRegularMember(h) || h.Typeflag == tar.TypeDir || isLink) {
		return backupErrorf("Unsafe special bundle entry: %s", h.Name)
	}
	if isLink {
		if h.Linkname == "" || strings.HasPrefix(h.Linkname, "/") {
			return backupErrorf("Unsafe bundle link: %s", h.Name)
		}
		resolved := resolvedLinkName(h)
		if resolved == ".." || strings.HasPrefix(resolved, "../") {
			return backupErrorf("Unsafe bundle link: %s", h.Name)
		}
	}
	return nil
}

// resolvedLinkName: symbolic-link targets are relative to the link's
// directory, hard-link names to the archive root; "" for other members.
func resolvedLinkName(h *tar.Header) string {
	switch h.Typeflag {
	case tar.TypeSymlink:
		return pyNormpath(pyJoin(pyDirname(pyNormpath(h.Name)), h.Linkname))
	case tar.TypeLink:
		return pyNormpath(h.Linkname)
	}
	return ""
}

type memberPolicy func(h *tar.Header, name string, pax map[string]string) error

// eachMember walks a tar.gz archive, handing every member with the pax
// records that apply to it (global ones included, as Python's tarfile does).
func eachMember(p string, visit func(h *tar.Header, pax map[string]string, body io.Reader) error) error {
	f, err := os.Open(p)
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return backupErrorf("%s is not a gzip archive: %v", filepath.Base(p), err)
	}
	defer gz.Close()
	reader := tar.NewReader(gz)
	global := map[string]string{}
	for {
		h, err := reader.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return backupErrorf("%s is not a readable tar archive: %v", filepath.Base(p), err)
		}
		if h.Typeflag == tar.TypeXGlobalHeader {
			for k, v := range h.PAXRecords {
				global[k] = v
			}
			continue
		}
		pax := map[string]string{}
		for k, v := range global {
			pax[k] = v
		}
		for k, v := range h.PAXRecords {
			pax[k] = v
		}
		if err := visit(h, pax, reader); err != nil {
			return err
		}
	}
}

// validateArchiveMembers checks every member and returns their names and
// total expanded size.
func validateArchiveMembers(p, label string, maxMembers, maxBytes int64, policy memberPolicy) (map[string]bool, int64, error) {
	seen := map[string]bool{}
	var count, expanded int64
	err := eachMember(p, func(h *tar.Header, pax map[string]string, _ io.Reader) error {
		if err := validateBundleMember(h); err != nil {
			return err
		}
		name := pyNormpath(h.Name)
		if seen[name] {
			return backupErrorf("Duplicate %s archive member: %s", label, name)
		}
		seen[name] = true
		count++
		if count > maxMembers {
			return backupErrorf("%s archive exceeds the member-count limit (%d).", label, maxMembers)
		}
		if h.Size < 0 {
			return backupErrorf("Invalid %s archive member size: %s", label, name)
		}
		expanded += h.Size
		if expanded > maxBytes {
			return backupErrorf("%s archive exceeds the expanded-size limit (%d bytes).", label, maxBytes)
		}
		return policy(h, name, pax)
	})
	if err != nil {
		return nil, 0, err
	}
	return seen, expanded, nil
}

func outerMemberPolicy(h *tar.Header, name string, _ map[string]string) error {
	if !contains(outerRequired, name) && !contains(outerOptional, name) {
		return backupErrorf("Unexpected outer backup member: %s", name)
	}
	if !isRegularMember(h) {
		return backupErrorf("Outer backup member is not a regular file: %s", name)
	}
	return nil
}

func rejectPrivilegedPayloadAttributes(h *tar.Header, pax map[string]string) error {
	if h.Mode&0o6000 != 0 {
		return backupErrorf("Unsafe setuid/setgid payload entry: %s", h.Name)
	}
	for key := range pax {
		if strings.HasPrefix(key, "SCHILY.xattr.security.") {
			return backupErrorf("Unsafe security xattr in payload entry: %s", h.Name)
		}
	}
	return nil
}

func coreMemberPolicy(h *tar.Header, name string, pax map[string]string) error {
	if err := rejectPrivilegedPayloadAttributes(h, pax); err != nil {
		return err
	}
	p := "/" + strings.TrimLeft(name, "/")
	allowed := corePayloadPathAllowed(p)
	if h.Typeflag == tar.TypeDir {
		allowed = allowed || coreAncestorDirectoryAllowed(p)
	}
	if !allowed {
		return backupErrorf("Core payload member is outside managed paths: %s", name)
	}
	if target := resolvedLinkName(h); target != "" && !corePayloadPathAllowed("/"+strings.TrimLeft(target, "/")) {
		return backupErrorf("Core payload link target is outside managed paths: %s", name)
	}
	return nil
}

func sshMemberPolicy(h *tar.Header, name string, pax map[string]string) error {
	if err := rejectPrivilegedPayloadAttributes(h, pax); err != nil {
		return err
	}
	p := "/" + strings.TrimLeft(name, "/")
	allowed := sshPayloadPathAllowed(p)
	if h.Typeflag == tar.TypeDir {
		allowed = allowed || sshAncestorDirectoryAllowed(p)
	}
	if !allowed {
		return backupErrorf("SSH payload member is outside allowed paths: %s", name)
	}
	if target := resolvedLinkName(h); target != "" && !sshPayloadPathAllowed("/"+strings.TrimLeft(target, "/")) {
		return backupErrorf("SSH payload link target is outside allowed paths: %s", name)
	}
	return nil
}

// extractBundle checks the outer archive, then writes its regular files.
// The members are checked again as they are written, so an archive changed
// between the two reads cannot place anything else.
func extractBundle(bundle, destination string) error {
	members, expanded, err := validateArchiveMembers(bundle, "outer backup", limit.outerMembers, limit.outerBytes, outerMemberPolicy)
	if err != nil {
		return err
	}
	var missing []string
	for _, name := range outerRequired {
		if !members[name] {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return backupErrorf("Outer backup is missing required members: %s", strings.Join(missing, ", "))
	}
	usage, err := diskUsage(destination)
	if err != nil {
		return err
	}
	if required := expanded + limit.restoreMinFree; usage.free < required {
		return backupErrorf("Not enough temporary disk space to inspect the backup: need %s, have %s.",
			formatBytes(required), formatBytes(usage.free))
	}
	written := map[string]bool{}
	return eachMember(bundle, func(h *tar.Header, pax map[string]string, body io.Reader) error {
		if err := validateBundleMember(h); err != nil {
			return err
		}
		name := pyNormpath(h.Name)
		if err := outerMemberPolicy(h, name, pax); err != nil {
			return err
		}
		if written[name] {
			return backupErrorf("Duplicate outer backup archive member: %s", name)
		}
		written[name] = true
		target := filepath.Join(destination, name)
		_ = os.Remove(target)
		out, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return err
		}
		if _, err := io.Copy(out, io.LimitReader(body, limit.outerBytes+1)); err != nil {
			out.Close()
			return err
		}
		return out.Close()
	})
}

func validatePayload(p string, ssh bool) (int64, error) {
	if ssh {
		_, expanded, err := validateArchiveMembers(p, "SSH payload", limit.sshMembers, limit.sshBytes, sshMemberPolicy)
		return expanded, err
	}
	_, expanded, err := validateArchiveMembers(p, "core payload", limit.coreMembers, limit.coreBytes, coreMemberPolicy)
	return expanded, err
}

// validateRollbackPayload checks a local safety snapshot that may hold core
// and SSH state.
var validateRollbackPayload = func(p string, includeSSH bool) error {
	if !includeSSH {
		_, err := validatePayload(p, false)
		return err
	}
	policy := func(h *tar.Header, name string, pax map[string]string) error {
		coreErr := coreMemberPolicy(h, name, pax)
		if coreErr == nil {
			return nil
		}
		if sshMemberPolicy(h, name, pax) == nil {
			return nil
		}
		return coreErr
	}
	_, _, err := validateArchiveMembers(p, "rollback payload", limit.coreMembers+limit.sshMembers,
		limit.coreBytes+limit.sshBytes, policy)
	return err
}

// createPayload archives the paths and returns what tar wanted to say. Exit
// 1 means files changed while being read -- routine on a gateway, where
// haproxy.log is appended to several times a second -- so it is reported in
// the manifest, not fatal; 2 is a fatal error.
func createPayload(destination string, paths, excludes []string) ([]string, error) {
	if len(paths) == 0 {
		return nil, backupErrorf("No files were found for the backup payload.")
	}
	argv := []string{"tar", "--acls", "--xattrs", "--numeric-owner", "-czpf", destination, "-C", "/"}
	for _, value := range excludes {
		argv = append(argv, "--exclude="+value)
	}
	argv = append(argv, relativePaths(paths)...)
	result, err := run(argv, runOptions{capture: true})
	if err != nil {
		return nil, err
	}
	warnings := []string{}
	for _, line := range splitLines(result.Stderr) {
		if line = strings.TrimSpace(line); line != "" {
			warnings = append(warnings, line)
		}
	}
	if result.Code >= 2 {
		tail := warnings
		if len(tail) > 10 {
			tail = tail[len(tail)-10:]
		}
		detail := strings.Join(tail, " | ")
		if detail == "" {
			detail = "tar gave no reason"
		}
		return nil, backupErrorf("tar failed with exit code %d: %s", result.Code, detail)
	}
	if err := os.Chmod(destination, 0o600); err != nil {
		return nil, err
	}
	return warnings, nil
}

// extractPayload extracts over "/"; with members, only those (and what is
// below them). Full extractions preserve host broker/control-plane subtrees
// (such as backup-web) so a live web restore cannot overwrite its own job
// files or recovery source.
var extractPayload = func(payload string, members []string) error {
	argv := []string{"tar", "--acls", "--xattrs", "--xattrs-exclude=security.*", "--numeric-owner", "-xzpf", payload, "-C", "/"}
	if len(members) == 0 {
		for _, rel := range relativePaths(effectiveRestorePreservedPaths()) {
			argv = append(argv, "--exclude="+rel, "--exclude=./"+rel)
		}
	}
	argv = append(argv, members...)
	_, err := run(argv, runOptions{check: true})
	return err
}

func listPayloadMembers(payload string) ([]string, error) {
	result, err := run([]string{"tar", "-tzf", payload}, runOptions{check: true, capture: true})
	if err != nil {
		return nil, err
	}
	var members []string
	for _, line := range splitLines(result.Stdout) {
		if line = strings.TrimSpace(line); line != "" {
			members = append(members, line)
		}
	}
	return members, nil
}

// configScopeMembers is the archive member prefixes the configuration scope covers.
var configScopeMembers = func(payload string) ([]string, error) {
	members, err := listPayloadMembers(payload)
	if err != nil {
		return nil, err
	}
	selected := map[string]bool{}
	for _, member := range members {
		name := strings.TrimRight(strings.TrimLeft(member, "./"), "/")
		for _, root := range configScopePaths {
			prefix := strings.TrimLeft(root, "/")
			if name == prefix || strings.HasPrefix(name, prefix+"/") {
				selected[prefix] = true
			}
		}
	}
	return sortedKeys(selected), nil
}
