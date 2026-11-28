package certd

import (
	"bytes"
	"crypto/x509"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/hostfile"
	"github.com/CLLlAgOB/easy-ha-proxy/go/agent/internal/pyx"
)

var pemLabels = []string{"PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY", "CERTIFICATE"}

// normaliseUploadedPEM is normalise_uploaded_pem.
func normaliseUploadedPEM(parts ...[]byte) ([]byte, error) {
	seen := map[string]bool{}
	certs, keys := [][]byte{}, [][]byte{}
	for _, part := range parts {
		if len(part) == 0 {
			continue
		}
		for _, label := range pemLabels {
			blocks, err := extractPEMBlocks(part, label)
			if err != nil {
				return nil, err
			}
			for _, block := range blocks {
				normalised := bytes.TrimSpace(block)
				fp := string(bytes.Join(bytes.Fields(normalised), nil))
				if seen[fp] {
					continue
				}
				seen[fp] = true
				if label == "CERTIFICATE" {
					certs = append(certs, normalised)
				} else {
					keys = append(keys, normalised)
				}
			}
		}
	}
	if len(certs) == 0 {
		return nil, vErr("no certificate was found in what was uploaded")
	}
	if len(keys) == 0 {
		return nil, vErr("no private key was found; the certificate on its own cannot be used to serve a site")
	}
	if len(keys) > 1 {
		return nil, vErr("%d different private keys were found; upload the one that belongs to this certificate", len(keys))
	}
	return append(bytes.Join(append(certs, keys...), []byte("\n")), '\n'), nil
}

func standbySlot(value any) (string, error) {
	slug, err := safeSlug(strings.TrimSpace(pyx.StrOr(value)))
	if err != nil {
		return "", err
	}
	if len([]rune(slug)) > 64 {
		return "", vErr("the standby name is too long")
	}
	return slug, nil
}

func (d *Daemon) standbyPath(domain, slot string) (string, error) {
	root := d.Opts.CertsAvailableDir
	s, err := safeSlug(domain)
	if err != nil {
		return "", err
	}
	holder, err := ensureWithin(root, filepath.Join(root, s))
	if err != nil {
		return "", err
	}
	return ensureWithin(holder, filepath.Join(holder, slot+".pem"))
}

func (d *Daemon) pinPath(stemName string) (string, error) {
	root := d.Opts.CertsAvailableDir
	s, err := safeSlug(stemName)
	if err != nil {
		return "", err
	}
	holder, err := ensureWithin(root, filepath.Join(root, s))
	if err != nil {
		return "", err
	}
	return ensureWithin(holder, filepath.Join(holder, pinFile))
}

func stemDomain(s string) string {
	for _, sfx := range []string{"-ecdsa", "-rsa"} {
		if strings.HasSuffix(s, sfx) {
			return strings.TrimSuffix(s, sfx)
		}
	}
	return s
}

func standbyKey(value any) (string, error) {
	raw := strings.ToLower(strings.TrimSpace(pyx.StrOr(value)))
	if raw == "" {
		return "", vErr("a certificate name is required")
	}
	if len([]rune(raw)) > 200 {
		return "", vErr("that certificate name is too long")
	}
	if _, err := normalizeDNSName(stemDomain(raw), false); err != nil {
		return "", err
	}
	if s, err := safeSlug(raw); err != nil || s != raw {
		return "", vErr("that certificate name cannot be used as a file name")
	}
	return raw, nil
}

func (d *Daemon) readPin(stemName string) string {
	path, err := d.pinPath(stemName)
	if err != nil || !isFile(path) {
		return ""
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return pyx.TruncRunes(strings.TrimSpace(string(raw)), 64)
}

func (d *Daemon) writePin(stemName, slot string) error {
	path, err := d.pinPath(stemName)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return hostfile.WriteAtomic(path, []byte(slot+"\n"), 0o644)
}

func (d *Daemon) clearPin(stemName string) error {
	path, err := d.pinPath(stemName)
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func (d *Daemon) standbyEntries(domain string) []map[string]any {
	holder := filepath.Join(d.Opts.CertsAvailableDir, mustSlug(domain))
	if !isDir(holder) {
		return []map[string]any{}
	}
	entries := []map[string]any{}
	for _, path := range globSorted(filepath.Join(holder, "*.pem")) {
		raw, err := os.ReadFile(path)
		var described map[string]any
		if err == nil {
			described, err = describePEM(raw)
		}
		if err != nil {
			entries = append(entries, map[string]any{"slot": stem(path), "error": pyx.TruncRunes(err.Error(), 200), "usable": false})
			continue
		}
		described["slot"] = stem(path)
		entries = append(entries, described)
	}
	sort.SliceStable(entries, func(i, j int) bool {
		ui, uj := entries[i]["usable"] == true, entries[j]["usable"] == true
		if ui != uj {
			return ui
		}
		return pyx.Str(entries[i]["slot"]) < pyx.Str(entries[j]["slot"])
	})
	return entries
}

func (d *Daemon) namesClaimedBy(path string) []string {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	certs, err := loadPEMCertificates(raw)
	if err != nil || len(certs) == 0 {
		return nil
	}
	return certDNSNames(certs[0])
}

func (d *Daemon) listStandbyCertificates() map[string]any {
	dir := d.Opts.HAProxyCertsDir
	domains := []any{}
	pems := globSorted(filepath.Join(dir, "*.pem"))
	for _, path := range pems {
		domain := stem(path)
		raw, err := os.ReadFile(path)
		var active map[string]any
		if err == nil {
			active, err = describePEM(raw)
		}
		if err != nil {
			active = map[string]any{"error": pyx.TruncRunes(err.Error(), 200), "usable": false}
		}
		standbys := d.standbyEntries(domain)
		pinned := d.readPin(domain)
		claimed := d.namesClaimedBy(path)
		servedElsewhere := map[string]bool{}
		for _, other := range pems {
			if filepath.Base(other) == filepath.Base(path) {
				continue
			}
			for _, n := range d.namesClaimedBy(other) {
				servedElsewhere[strings.ToLower(n)] = true
			}
		}
		canPutAway := len(claimed) > 0
		for _, n := range claimed {
			if !strings.HasPrefix(n, "*.") && !servedElsewhere[strings.ToLower(n)] {
				canPutAway = false
			}
		}
		usable := false
		standbyAny := []any{}
		for _, e := range standbys {
			if e["usable"] == true {
				usable = true
			}
			standbyAny = append(standbyAny, e)
		}
		domains = append(domains, map[string]any{"can_be_put_away": canPutAway, "domain": domain, "active": active,
			"standbys": standbyAny, "pinned": pinned, "renewal_paused": pinned != "", "has_usable_standby": usable})
	}
	return map[string]any{"ok": true, "domains": domains}
}

func pemArg(v any) []byte {
	switch x := v.(type) {
	case string:
		return []byte(x)
	case []byte:
		return x
	case nil:
		return nil
	}
	return []byte(fmt.Sprint(v))
}

func (d *Daemon) storeStandbyCertificate(domain, slot any, pemValue []byte) (map[string]any, error) {
	checkedDomain, err := standbyKey(domain)
	if err != nil {
		return nil, err
	}
	checkedSlot, err := standbySlot(slot)
	if err != nil {
		return nil, err
	}
	if checkedSlot == letsencryptSlot {
		return nil, vErr("%s is reserved for the renewing certificate", pyRepr(letsencryptSlot))
	}
	if len(bytes.TrimSpace(pemValue)) == 0 {
		return nil, vErr("no certificate was supplied")
	}
	if len(pemValue) > 1024*1024 {
		return nil, vErr("the certificate is implausibly large")
	}
	data, err := normaliseUploadedPEM(pemValue)
	if err != nil {
		return nil, err
	}
	if _, _, err := validateServerPEM(data, stemDomain(checkedDomain)); err != nil {
		return nil, err
	}
	described, err := describePEM(data)
	if err != nil {
		return nil, err
	}
	path, err := d.standbyPath(checkedDomain, checkedSlot)
	if err != nil {
		return nil, err
	}
	d.standbyMu.Lock()
	defer d.standbyMu.Unlock()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	if err := replaceServerPEMWithoutReload(path, data); err != nil {
		return nil, err
	}
	log.Printf("Stored standby certificate %s for %s", checkedSlot, checkedDomain)
	described["slot"] = checkedSlot
	return map[string]any{"ok": true, "domain": checkedDomain, "standby": described}, nil
}

func (d *Daemon) deployedStems() []string {
	out := []string{}
	for _, p := range globSorted(filepath.Join(d.Opts.HAProxyCertsDir, "*.pem")) {
		out = append(out, stem(p))
	}
	sort.Strings(out)
	return out
}

func siblingStem(s string) string {
	if strings.HasSuffix(s, "-ecdsa") {
		return strings.TrimSuffix(s, "-ecdsa") + "-rsa"
	}
	if strings.HasSuffix(s, "-rsa") {
		return strings.TrimSuffix(s, "-rsa") + "-ecdsa"
	}
	return ""
}

func (d *Daemon) storeStandbyForCoveredNames(slot any, pemValue []byte, exclude []string) (map[string]any, error) {
	checkedSlot, err := standbySlot(slot)
	if err != nil {
		return nil, err
	}
	if len(bytes.TrimSpace(pemValue)) == 0 {
		return nil, vErr("no certificate was supplied")
	}
	data, err := normaliseUploadedPEM(pemValue)
	if err != nil {
		return nil, err
	}
	certs, err := loadPEMCertificates(data)
	if err != nil {
		return nil, err
	}
	if len(certs) == 0 {
		return nil, vErr("PEM does not contain an X.509 certificate")
	}
	covered, skipped := []string{}, []string{}
	for _, s := range d.deployedStems() {
		if containsStr(exclude, s) {
			continue
		}
		if certMatchesDomain(certs[0], stemDomain(s)) {
			covered = append(covered, s)
		} else {
			skipped = append(skipped, s)
		}
	}
	if len(covered) == 0 {
		return nil, vErr("this certificate does not cover any name deployed on this gateway")
	}
	stored := []any{}
	for _, s := range covered {
		res, err := d.storeStandbyCertificate(s, checkedSlot, data)
		if err != nil {
			return nil, err
		}
		entry := map[string]any{"domain": s}
		for k, v := range pyx.Map(res["standby"]) {
			entry[k] = v
		}
		stored = append(stored, entry)
	}
	log.Printf("Stored standby %s for %d name(s): %s", checkedSlot, len(covered), strings.Join(covered, ", "))
	return map[string]any{"ok": true, "slot": checkedSlot, "domains": covered, "not_covered": skipped, "stored": stored}, nil
}

func (d *Daemon) adoptDeployedAsStandby(domain, slot any) (map[string]any, error) {
	s, err := standbyKey(domain)
	if err != nil {
		return nil, err
	}
	checkedSlot, err := standbySlot(slot)
	if err != nil {
		return nil, err
	}
	dir := d.Opts.HAProxyCertsDir
	source, err := ensureWithin(dir, filepath.Join(dir, mustSlug(s)+".pem"))
	if err != nil {
		return nil, err
	}
	if !isFile(source) {
		return nil, vErr("no certificate is deployed as %s", s)
	}
	data, err := os.ReadFile(source)
	if err != nil {
		return nil, err
	}
	if _, _, err := validateServerPEM(data, ""); err != nil {
		return nil, err
	}
	still := map[string]bool{}
	for _, p := range globSorted(filepath.Join(dir, "*.pem")) {
		if resolvePath(p) == resolvePath(source) {
			continue
		}
		for _, n := range d.namesClaimedBy(p) {
			still[strings.ToLower(n)] = true
		}
	}
	orphaned := []string{}
	for _, n := range d.namesClaimedBy(source) {
		if !strings.HasPrefix(n, "*.") && !still[strings.ToLower(n)] {
			orphaned = append(orphaned, n)
		}
	}
	if len(orphaned) > 0 {
		sort.Strings(orphaned)
		which := "that name"
		if len(orphaned) > 1 {
			which = "those names"
		}
		return nil, vErrS("this certificate is the only one serving " + strings.Join(orphaned, ", ") +
			"; putting it away would leave " + which + " without one")
	}
	stored, err := d.storeStandbyForCoveredNames(checkedSlot, data, []string{s})
	if err != nil {
		return nil, err
	}
	if err := os.Remove(source); err != nil {
		return nil, err
	}
	rc, _, stderr := d.reloadHAProxy()
	log.Printf("Took %s out of service and kept it as standby %s for %v", s, checkedSlot, stored["domains"])
	reloadErr := ""
	if !rcOK(rc) {
		reloadErr = pyx.TruncRunes(strings.TrimSpace(stderr), 400)
	}
	return map[string]any{"ok": rcOK(rc), "removed": s, "slot": checkedSlot, "domains": stored["domains"],
		"reload_rc": rcValue(rc), "reload_error": reloadErr}, nil
}

type pemChange struct {
	stem string
	data []byte // nil: leave the file as it is
}

// switchCertificateFiles is _switch_certificate_files.
func (d *Daemon) switchCertificateFiles(changes []pemChange, pin *string) (bool, *int, string, error) {
	dir := d.Opts.HAProxyCertsDir
	pems := []touchedPEM{}
	type pinSnap struct {
		stem, path string
		previous   []byte
		had        bool
	}
	pins := []pinSnap{}
	for _, c := range changes {
		dest, err := ensureWithin(dir, filepath.Join(dir, mustSlug(c.stem)+".pem"))
		if err != nil {
			return false, nil, "", err
		}
		prev, perr := os.ReadFile(dest)
		if perr != nil && !os.IsNotExist(perr) {
			return false, nil, "", perr
		}
		pems = append(pems, touchedPEM{c.stem, dest, prev, perr == nil})
		pp, err := d.pinPath(c.stem)
		if err != nil {
			return false, nil, "", err
		}
		pprev, perr2 := os.ReadFile(pp)
		if perr2 != nil && !os.IsNotExist(perr2) {
			return false, nil, "", perr2
		}
		pins = append(pins, pinSnap{c.stem, pp, pprev, perr2 == nil})
	}
	var rc *int
	active := changes[0].stem
	err := func() error {
		if pin != nil {
			for _, c := range changes {
				active = c.stem
				if err := d.writePin(c.stem, *pin); err != nil {
					return err
				}
			}
		}
		for i, c := range changes {
			active = c.stem
			if c.data == nil {
				continue
			}
			ok, r, _, stderr, err := d.activateServerPEM(pems[i].dest, c.data, true, true)
			rc = r
			if err != nil {
				return err
			}
			if !ok {
				msg := strings.TrimSpace(stderr)
				if msg == "" {
					msg = "HAProxy refused it"
				}
				return fmt.Errorf("%s", pyx.TruncRunes(msg, 200))
			}
		}
		if pin == nil {
			for _, c := range changes {
				active = c.stem
				if err := d.clearPin(c.stem); err != nil {
					return err
				}
			}
		}
		return nil
	}()
	if err == nil {
		return true, rc, "", nil
	}
	errText := active + ": " + pyx.TruncRunes(err.Error(), 200) + d.putBackPEMs(pems)
	pinErrors := []string{}
	for _, p := range pins {
		cur, cerr := os.ReadFile(p.path)
		have := cerr == nil
		if have == p.had && (!have || bytes.Equal(cur, p.previous)) {
			continue
		}
		var werr error
		if !p.had {
			if rerr := os.Remove(p.path); rerr != nil && !os.IsNotExist(rerr) {
				werr = rerr
			}
		} else {
			werr = func() error {
				tmp, err := os.CreateTemp(filepath.Dir(p.path), ".pin-")
				if err != nil {
					return err
				}
				name := tmp.Name()
				defer os.Remove(name)
				if _, err := tmp.Write(p.previous); err != nil {
					_ = tmp.Close()
					return err
				}
				_ = tmp.Chmod(0o644)
				_ = tmp.Close()
				return os.Rename(name, p.path)
			}()
		}
		if werr != nil {
			pinErrors = append(pinErrors, fmt.Sprintf("%s (%v)", p.stem, werr))
		}
	}
	if len(pinErrors) > 0 {
		errText += "; restoring holds failed for " + strings.Join(pinErrors, ", ")
	}
	return false, rc, errText, nil
}

func (d *Daemon) activateStandbyCertificate(domain, slot any) (map[string]any, error) {
	checkedDomain, err := standbyKey(domain)
	if err != nil {
		return nil, err
	}
	checkedSlot, err := standbySlot(slot)
	if err != nil {
		return nil, err
	}
	d.standbyMu.Lock()
	stems := []string{checkedDomain}
	if sib := siblingStem(checkedDomain); sib != "" {
		if p, err := d.standbyPath(sib, checkedSlot); err == nil && isFile(p) {
			stems = append(stems, sib)
		}
	}
	changes := []pemChange{}
	descriptions := []map[string]any{}
	for _, s := range stems {
		path, err := d.standbyPath(s, checkedSlot)
		if err != nil {
			d.standbyMu.Unlock()
			return nil, err
		}
		if !isFile(path) {
			d.standbyMu.Unlock()
			return nil, vErr("no standby named %s for this name", pyRepr(checkedSlot))
		}
		data, err := os.ReadFile(path)
		if err != nil {
			d.standbyMu.Unlock()
			return nil, err
		}
		if _, _, err := validateServerPEM(data, stemDomain(s)); err != nil {
			d.standbyMu.Unlock()
			return nil, err
		}
		described, err := describePEM(data)
		if err != nil {
			d.standbyMu.Unlock()
			return nil, err
		}
		if described["usable"] != true {
			d.standbyMu.Unlock()
			return nil, vErr("that standby is not valid today (%s to %s)", described["not_before"], described["not_after"])
		}
		changes = append(changes, pemChange{s, data})
		descriptions = append(descriptions, described)
	}
	ok, rc, stderr, err := d.switchCertificateFiles(changes, &checkedSlot)
	d.standbyMu.Unlock()
	if err != nil {
		return nil, err
	}
	described := descriptions[0]
	if ok {
		log.Printf("Standby certificate %s put into service for %s (issuer %v)", checkedSlot, checkedDomain, described["issuer"])
	} else {
		log.Printf("Standby certificate %s not put into service for %s: %s", checkedSlot, checkedDomain, stderr)
	}
	also := []string{}
	if ok {
		also = stems[1:]
	}
	return map[string]any{"ok": ok, "domain": checkedDomain, "slot": checkedSlot, "also_switched": also,
		"issuer": described["issuer"], "not_after": described["not_after"], "reload_rc": rcValue(rc), "reload_error": stderr}, nil
}

func (d *Daemon) releaseToLetsEncrypt(domain any) (map[string]any, error) {
	s, err := standbyKey(domain)
	if err != nil {
		return nil, err
	}
	d.standbyMu.Lock()
	if d.readPin(s) == "" {
		d.standbyMu.Unlock()
		return nil, vErr("that name is not being held on a standby")
	}
	stems := []string{s}
	if sib := siblingStem(s); sib != "" && d.readPin(sib) != "" {
		stems = append(stems, sib)
	}
	changes := []pemChange{}
	available := []bool{}
	for _, name := range stems {
		live := filepath.Join(d.leLiveDir(), name)
		fullchain, privkey := filepath.Join(live, "fullchain.pem"), filepath.Join(live, "privkey.pem")
		var data []byte
		if isFile(fullchain) && isFile(privkey) {
			a, err1 := os.ReadFile(fullchain)
			b, err2 := os.ReadFile(privkey)
			if err1 != nil || err2 != nil {
				d.standbyMu.Unlock()
				return nil, firstErr(err1, err2)
			}
			data = append(a, b...)
			if _, _, err := validateServerPEM(data, stemDomain(name)); err != nil {
				d.standbyMu.Unlock()
				return nil, err
			}
		}
		changes = append(changes, pemChange{name, data})
		available = append(available, data != nil)
	}
	anyAvail, allAvail := false, true
	for _, a := range available {
		anyAvail = anyAvail || a
		allAvail = allAvail && a
	}
	if anyAvail && !allAvail {
		d.standbyMu.Unlock()
		return nil, vErr("both renewing certificates must be on disk to restore this pair")
	}
	ok, rc, stderr, err := d.switchCertificateFiles(changes, nil)
	d.standbyMu.Unlock()
	if err != nil {
		return nil, err
	}
	also := []string{}
	if ok {
		also = stems[1:]
	}
	result := map[string]any{"ok": ok, "domain": s, "restored": ok && allAvail, "also_released": also,
		"reload_rc": rcValue(rc), "reload_error": stderr}
	if ok {
		log.Printf("Released %s back to the renewing certificate", strings.Join(stems, ", "))
		if !allAvail {
			result["message"] = "released; no Let's Encrypt certificate is on disk yet"
		}
	} else {
		log.Printf("Cannot release %s back to the renewing certificate: %s", strings.Join(stems, ", "), stderr)
	}
	return result, nil
}

func firstErr(errs ...error) error {
	for _, e := range errs {
		if e != nil {
			return e
		}
	}
	return nil
}

func (d *Daemon) deleteStandbyCertificate(domain, slot any, actor string) (map[string]any, error) {
	checkedDomain, err := standbyKey(domain)
	if err != nil {
		return nil, err
	}
	checkedSlot, err := standbySlot(slot)
	if err != nil {
		return nil, err
	}
	d.standbyMu.Lock()
	defer d.standbyMu.Unlock()
	if d.readPin(checkedDomain) == checkedSlot {
		return nil, vErr("that standby is in service; hand the name back to Let's Encrypt before removing it")
	}
	path, err := d.standbyPath(checkedDomain, checkedSlot)
	if err != nil {
		return nil, err
	}
	kept := ""
	if isFile(path) {
		details := d.certDetails(path)
		details["slot"] = checkedSlot
		if kept, err = d.trashPut("standby", fmt.Sprintf("%s (%s)", checkedDomain, checkedSlot), []string{path}, actor, details, nil); err != nil {
			return nil, err
		}
	}
	before := trashListing([]string{path})
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		d.trashSettle(kept, before, []string{path})
		return nil, err
	}
	d.trashCommit(kept)
	holder := filepath.Dir(path)
	if entries, err := os.ReadDir(holder); err == nil && len(entries) == 0 {
		_ = os.Remove(holder)
	}
	log.Printf("Deleted standby certificate %s for %s", checkedSlot, checkedDomain)
	return map[string]any{"ok": true, "domain": checkedDomain, "slot": checkedSlot}, nil
}

func (d *Daemon) standbyHint(domain string) string {
	var best map[string]any
	for _, e := range d.standbyEntries(domain) {
		if e["usable"] != true {
			continue
		}
		if best == nil || pyx.Float(e["days_left"]) > pyx.Float(best["days_left"]) {
			best = e
		}
	}
	if best == nil {
		return ""
	}
	return fmt.Sprintf(". A standby is ready: %v from %v, valid until %v", best["slot"], best["issuer"], best["not_after"])
}

func (d *Daemon) certDetails(path string) map[string]any {
	if item := buildCertItemForList(path); item != nil {
		domains := item["domains"]
		if domains == nil {
			domains = []string{}
		}
		return map[string]any{"domains": domains, "not_after": item["not_after"]}
	}
	return map[string]any{}
}

var _ = x509.Certificate{}
