package stages

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"easy-ha-proxy/panel/shared/jinja"
	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/apply/engine"
)

// cert's entries run only by hand: rdg (crt-rdg) and remove_orphans
// (remove_site).
func init() {
	register(Stage{Name: "cert-manual", Parts: []Part{
		{Name: "cert/rdg", Role: "cert", File: "rdg", Build: certRDG},
		{Name: "cert/remove_orphans", Role: "cert", File: "remove_orphans", Build: certRemoveOrphans},
	}})
}

// certRDG is rdg.yml: the SFTP key, the hook's environment and the post-hook
// that sends the certificate to an RD Gateway as a PFX.
func certRDG(b *Builder) []engine.Step {
	return []engine.Step{
		{Name: "Ensure post-hooks directory exists", Resource: b.Dir("/etc/letsencrypt/renewal-hooks/post", "root", "root", "0755")},
		{Name: "Ensure /root/.ssh exists", Resource: b.Dir("/root/.ssh", "root", "root", "0700")},
		{Name: "Copy RDG SSH private key",
			Build: b.CopySrc("{{ playbook_dir }}/../credentials/.ssh/id_rdg_cert", "/root/.ssh/id_rdg_cert", "root", "root", "0600")},
		{Name: "RDG env for post-hook", Build: b.CopyContent(rdgEnv, "/etc/letsencrypt/rdg.env", "root", "root", "0600")},
		{Name: "POST-hook — RDG deploy + HAProxy reload",
			Build: b.CopyContent(rdgPostHook, "/etc/letsencrypt/renewal-hooks/post/900-post-deploy-rdg.sh", "root", "root", "0755")},
	}
}

var (
	confSuffix = regexp.MustCompile(`\.conf$`)
	pemSuffix  = regexp.MustCompile(`pem$`)
	// The task writes '\\.$' inside {{ }} in a folded scalar: Ansible doubles
	// the backslashes, so the pattern is a backslash and any character, which
	// a file name never ends with -- the trailing dot is never stripped, and
	// every PEM without a lineage of its own counts as an orphan. Kept as
	// Ansible does it; see the transcription's commit message.
	dotSuffix = regexp.MustCompile(`\\.$`)
)

func baseNames(dir, suffix string) []string {
	entries, _ := os.ReadDir(dir)
	var out []string
	for _, e := range entries {
		if e.Type().IsRegular() && strings.HasSuffix(e.Name(), suffix) {
			out = append(out, e.Name())
		}
	}
	return out
}

// certRemoveOrphans is remove_orphans.yml: certbot lineages and assembled
// PEMs no target domain names any more, held standby names spared; with
// cleanup_dry_run only the report.
func certRemoveOrphans(b *Builder) []engine.Step {
	targets := unique(strList(b.Value("{{ certbot_domains | default([]) }}")))
	certsDir := b.S("{{ haproxy_certs_dir | default('/etc/haproxy/certs') }}")
	available := b.S("{{ haproxy_certs_available_dir | default('/etc/haproxy/certs-available') }}")
	dry := b.Bool("{{ cleanup_dry_run | default(false) | bool }}")
	var current, orphanLineages, orphanPEMs, pinned []string
	deletes := []*engine.Command{}
	steps := []engine.Step{
		assertStep("Validate that certbot_domains is defined", func(*engine.Run) bool { return len(targets) >= 1 },
			"certbot_domains is undefined or empty. Collect it in pre_tasks."),
		fact("Normalize the target domain list from pre_tasks", nil, func() error { return nil }),
		fact("Find current Certbot lineages (/etc/letsencrypt/renewal/*.conf)", nil, func() error {
			current = nil
			for _, name := range baseNames(b.Sys.Path("/etc/letsencrypt/renewal"), ".conf") {
				current = append(current, confSuffix.ReplaceAllString(name, ""))
			}
			return nil
		}),
		fact("Build the current Certbot lineage name list", nil, func() error { return nil }),
		fact("Calculate orphaned Certbot lineages by exact name", nil, func() error {
			orphanLineages = nil
			for _, lin := range current {
				if !contains(targets, keyTypeSuffix.ReplaceAllString(lin, "")) {
					orphanLineages = append(orphanLineages, lin)
				}
			}
			orphanLineages = unique(orphanLineages)
			sort.Strings(orphanLineages)
			return nil
		}),
		fact("Find assembled HAProxy PEM files", nil, func() error { return nil }),
		fact("Calculate PEM files matching orphaned lineages", nil, func() error { return nil }),
		fact("Calculate orphaned PEM files by root domain", nil, func() error { return nil }),
		fact("Find names held on a standby certificate", nil, func() error {
			pinned = nil
			filepath.WalkDir(b.Sys.Path(available), func(path string, d os.DirEntry, err error) error {
				if err == nil && d.Type().IsRegular() && d.Name() == ".pinned" {
					pinned = append(pinned, filepath.Base(filepath.Dir(path))+".pem")
				}
				return nil
			})
			return nil
		}),
		fact("Build the list of held PEM names", nil, func() error { return nil }),
		fact("Build the final orphaned PEM removal list", nil, func() error {
			pems := baseNames(b.Sys.Path(certsDir), ".pem")
			var candidates []string
			for _, p := range pems {
				if contains(orphanLineages, strings.TrimSuffix(p, ".pem")) && strings.HasSuffix(p, ".pem") {
					candidates = append(candidates, p) // exact
				}
			}
			for _, p := range pems {
				root := keyTypeSuffix.ReplaceAllString(dotSuffix.ReplaceAllString(pemSuffix.ReplaceAllString(p, ""), ""), "")
				if !contains(targets, root) {
					candidates = append(candidates, p) // by root
				}
			}
			orphanPEMs = nil
			for _, p := range unique(candidates) {
				if !contains(current, strings.TrimSuffix(p, ".pem")) && !contains(pinned, p) {
					orphanPEMs = append(orphanPEMs, p)
				}
			}
			sort.Strings(orphanPEMs)
			return nil
		}),
		{Name: "DRY-RUN | Show lineages and PEM files that would be removed", Build: func(*engine.Run) (engine.Resource, error) {
			sorted := func(in []string) []string { out := append([]string{}, in...); sort.Strings(out); return out }
			return report(fmt.Sprintf("Target domains      : %v\nLineages found      : %v\nLineages to delete  : %v\n*.pem   to delete   : %v\nheld                : %v\ncleanup_dry_run=%v",
				sorted(targets), sorted(current), orphanLineages, orphanPEMs, pinned, pyBool(dry))), nil
		}},
		{Name: "certbot delete orphaned lineages (non-interactive, quiet)", When: func(*engine.Run) bool { return !dry },
			Build: func(*engine.Run) (engine.Resource, error) {
				loop := &engine.Multi{Desc: "certbot delete"}
				deletes = deletes[:0]
				for _, lin := range orphanLineages {
					cmd := &engine.Command{Argv: []string{"/bin/sh", "-c", `exec certbot delete --non-interactive --quiet --cert-name "$0" 2>&1`, lin},
						IgnoreErrors: true, ChangedWhen: func(_ string, code int) bool { return code == 0 }}
					deletes = append(deletes, cmd)
					loop.Items = append(loop.Items, cmd)
				}
				return loop, nil
			}},
		{Name: "Report orphaned lineages certbot did not delete", Build: func(*engine.Run) (engine.Resource, error) {
			var kept []string
			for i, cmd := range deletes {
				if cmd.Code != 0 {
					kept = append(kept, fmt.Sprintf("certbot did not delete %s: %s", orphanLineages[i], strings.TrimSpace(cmd.Output)))
				}
			}
			if len(kept) == 0 {
				return nil, nil
			}
			return report(strings.Join(kept, "\n")), nil
		}},
		{Name: "Delete orphaned assembled HAProxy PEM files", When: func(*engine.Run) bool { return !dry },
			Build: func(*engine.Run) (engine.Resource, error) {
				loop := &engine.Multi{Desc: "absent PEMs"}
				for _, p := range orphanPEMs {
					loop.Items = append(loop.Items, &engine.Absent{Path: certsDir + "/" + p})
				}
				return loop, nil
			}},
		{Name: "Reload HAProxy after orphan cleanup", When: func(*engine.Run) bool { return !dry && len(orphanLineages) > 0 },
			Resource: Unit("haproxy", nil, "reloaded")},
	}
	_ = jinja.Str
	return steps
}

// pyBool is how Jinja prints a bool.
func pyBool(v bool) string {
	if v {
		return "True"
	}
	return "False"
}
