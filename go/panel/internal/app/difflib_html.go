package app

// difflib._mdiff and HtmlDiff.make_table (CPython 3.12), line by line.

import (
	"fmt"
	"regexp"
	"strings"
	"sync"
	"unicode"
)

// diffSide is one (line number, text) pair; num is an int, "" or ">".
type diffSide struct {
	num  any
	text string
}

// diffRow is one (fromdata, todata, flag) triple; a nil side is Python's None.
type diffRow struct {
	from, to *diffSide
	flag     bool
}

var changeRe = regexp.MustCompile(`(\++|-+|\^+)`)

type mdiffState struct {
	lines     []string
	diff      []string
	pos       int
	numLines  [2]int
	pending   int
	toYield   int
	queue     []diffRow
	finished  bool
	fromLines []struct {
		side diffSide
		flag bool
	}
	toLines []struct {
		side diffSide
		flag bool
	}
}

func (m *mdiffState) next() string {
	if m.pos >= len(m.diff) {
		return "X"
	}
	l := m.diff[m.pos]
	m.pos++
	return l
}

func runesSlice(s string, a, b int) string {
	r := []rune(s)
	if a > len(r) {
		a = len(r)
	}
	if b > len(r) {
		b = len(r)
	}
	if a > b {
		a = b
	}
	return string(r[a:b])
}

// makeLine is _make_line; copy=true pops from a copy (the ' ' case).
func (m *mdiffState) makeLine(lines *[]string, key byte, side int) diffSide {
	m.numLines[side]++
	pop := func() string {
		l := (*lines)[0]
		*lines = (*lines)[1:]
		return l
	}
	if key == 0 {
		return diffSide{m.numLines[side], runesSlice(pop(), 2, 1<<30)}
	}
	if key == '?' {
		text, markers := pop(), pop()
		type sub struct {
			key        string
			begin, end int
		}
		var subs []sub
		mr := []rune(markers)
		for _, loc := range changeRe.FindAllStringIndex(markers, -1) {
			b := len([]rune(markers[:loc[0]]))
			e := len([]rune(markers[:loc[1]]))
			subs = append(subs, sub{string(mr[b]), b, e})
		}
		for i := len(subs) - 1; i >= 0; i-- {
			sb := subs[i]
			text = runesSlice(text, 0, sb.begin) + "\x00" + sb.key + runesSlice(text, sb.begin, sb.end) + "\x01" + runesSlice(text, sb.end, 1<<30)
		}
		return diffSide{m.numLines[side], runesSlice(text, 2, 1<<30)}
	}
	text := runesSlice(pop(), 2, 1<<30)
	if text == "" {
		text = " "
	}
	return diffSide{m.numLines[side], "\x00" + string(key) + text + "\x01"}
}

// lineIteratorStep produces the next rows of _line_iterator into the queue;
// false when the generator has returned.
func (m *mdiffState) lineIteratorStep() bool {
	if m.finished {
		return false
	}
	blank := &diffSide{"", "\n"}
	for {
		for len(m.lines) < 4 {
			m.lines = append(m.lines, m.next())
		}
		var sb strings.Builder
		for _, l := range m.lines {
			if l == "" {
				continue
			}
			sb.WriteString(string([]rune(l)[0]))
		}
		s := sb.String()
		var fromLine, toLine *diffSide
		emit := func(f, t *diffSide, flag bool) { m.queue = append(m.queue, diffRow{f, t, flag}) }
		switch {
		case strings.HasPrefix(s, "X"):
			m.toYield = m.pending
		case strings.HasPrefix(s, "-?+?"):
			f := m.makeLine(&m.lines, '?', 0)
			t := m.makeLine(&m.lines, '?', 1)
			emit(&f, &t, true)
			return true
		case strings.HasPrefix(s, "--++"):
			m.pending--
			f := m.makeLine(&m.lines, '-', 0)
			emit(&f, nil, true)
			return true
		case strings.HasPrefix(s, "--?+") || strings.HasPrefix(s, "--+") || strings.HasPrefix(s, "- "):
			f := m.makeLine(&m.lines, '-', 0)
			fromLine, toLine = &f, nil
			m.toYield, m.pending = m.pending-1, 0
		case strings.HasPrefix(s, "-+?"):
			f := m.makeLine(&m.lines, 0, 0)
			t := m.makeLine(&m.lines, '?', 1)
			emit(&f, &t, true)
			return true
		case strings.HasPrefix(s, "-?+"):
			f := m.makeLine(&m.lines, '?', 0)
			t := m.makeLine(&m.lines, 0, 1)
			emit(&f, &t, true)
			return true
		case strings.HasPrefix(s, "-"):
			m.pending--
			f := m.makeLine(&m.lines, '-', 0)
			emit(&f, nil, true)
			return true
		case strings.HasPrefix(s, "+--"):
			m.pending++
			t := m.makeLine(&m.lines, '+', 1)
			emit(nil, &t, true)
			return true
		case strings.HasPrefix(s, "+ ") || strings.HasPrefix(s, "+-"):
			t := m.makeLine(&m.lines, '+', 1)
			fromLine, toLine = nil, &t
			m.toYield, m.pending = m.pending+1, 0
		case strings.HasPrefix(s, "+"):
			m.pending++
			t := m.makeLine(&m.lines, '+', 1)
			emit(nil, &t, true)
			return true
		case strings.HasPrefix(s, " "):
			cp := append([]string{}, m.lines...)
			f := m.makeLine(&cp, 0, 0)
			t := m.makeLine(&m.lines, 0, 1)
			emit(&f, &t, false)
			return true
		}
		for m.toYield < 0 {
			m.toYield++
			b := *blank
			emit(nil, &b, true)
		}
		for m.toYield > 0 {
			m.toYield--
			b := *blank
			emit(&b, nil, true)
		}
		if strings.HasPrefix(s, "X") {
			m.finished = true
			return len(m.queue) > 0
		}
		emit(fromLine, toLine, true)
		return true
	}
}

// mdiffRows is _mdiff(fromlines, tolines) with context=None.
func mdiffRows(fromlines, tolines []string) []diffRow {
	d := &differ{charjunk: isCharacterJunk}
	m := &mdiffState{diff: d.compare(fromlines, tolines)}
	var out []diffRow
	for {
		for len(m.fromLines) == 0 || len(m.toLines) == 0 {
			if len(m.queue) == 0 && !m.lineIteratorStep() {
				return out
			}
			if len(m.queue) == 0 {
				return out
			}
			r := m.queue[0]
			m.queue = m.queue[1:]
			if r.from != nil {
				m.fromLines = append(m.fromLines, struct {
					side diffSide
					flag bool
				}{*r.from, r.flag})
			}
			if r.to != nil {
				m.toLines = append(m.toLines, struct {
					side diffSide
					flag bool
				}{*r.to, r.flag})
			}
		}
		f := m.fromLines[0]
		m.fromLines = m.fromLines[1:]
		t := m.toLines[0]
		m.toLines = m.toLines[1:]
		fs, ts := f.side, t.side
		out = append(out, diffRow{&fs, &ts, f.flag || t.flag})
	}
}

// ---- HtmlDiff ----

var (
	htmlDiffMu     sync.Mutex
	htmlDiffPrefix int
)

const htmlTableTemplate = `
    <table class="diff" id="difflib_chg_%s_top"
           cellspacing="0" cellpadding="0" rules="groups" >
        <colgroup></colgroup> <colgroup></colgroup> <colgroup></colgroup>
        <colgroup></colgroup> <colgroup></colgroup> <colgroup></colgroup>
        %s
        <tbody>
%s        </tbody>
    </table>`

// MakeCfgHTMLDiff is make_cfg_html_diff.
func MakeCfgHTMLDiff(c *Ctx, serverCfg, renderedCfg string) string {
	from := pySplitlines(configForOperationalComparison(serverCfg))
	to := pySplitlines(configForOperationalComparison(renderedCfg))
	if len(from) == 0 && len(to) == 0 {
		return "<div class='mono notranslate' translate='no' data-i18n-skip>" + c.T("Both configurations are empty.") + "</div>"
	}
	table := htmlMakeTable(from, to, c.T("/etc/haproxy/haproxy.cfg (on server)"), c.T("haproxy.cfg (rendered from templates)"))
	return strings.Replace(table, `<table class="diff"`, `<table class="diff notranslate" translate="no" data-i18n-skip`, 1)
}

func htmlMakeTable(fromlines, tolines []string, fromdesc, todesc string) string {
	htmlDiffMu.Lock()
	n := htmlDiffPrefix
	htmlDiffPrefix++
	htmlDiffMu.Unlock()
	prefix := [2]string{fmt.Sprintf("from%d_", n), fmt.Sprintf("to%d_", n)}
	fromlines = tabNewlineReplace(fromlines)
	tolines = tabNewlineReplace(tolines)
	rows := lineWrapper(mdiffRows(fromlines, tolines))
	fromList, toList, flags := collectLines(rows, prefix)
	nextHref, nextID := convertFlags(&fromList, &toList, &flags, prefix[1], 3)
	var s strings.Builder
	for i := range flags {
		if flags[i] == nil {
			if i > 0 {
				s.WriteString("        </tbody>        \n        <tbody>\n")
			}
			continue
		}
		fmt.Fprintf(&s, "            <tr><td class=\"diff_next\"%s>%s</td>%s<td class=\"diff_next\">%s</td>%s</tr>\n",
			nextID[i], nextHref[i], fromList[i], nextHref[i], toList[i])
	}
	header := ""
	if fromdesc != "" || todesc != "" {
		header = `<thead><tr><th class="diff_next"><br /></th>` + fmt.Sprintf(`<th colspan="2" class="diff_header">%s</th>`, fromdesc) +
			`<th class="diff_next"><br /></th>` + fmt.Sprintf(`<th colspan="2" class="diff_header">%s</th>`, todesc) + `</tr></thead>`
	}
	table := fmt.Sprintf(htmlTableTemplate, prefix[1], header, s.String())
	return strings.NewReplacer("\x00+", `<span class="diff_add">`, "\x00-", `<span class="diff_sub">`,
		"\x00^", `<span class="diff_chg">`, "\x01", "</span>", "\t", "&nbsp;").Replace(table)
}

func tabNewlineReplace(lines []string) []string {
	out := make([]string, len(lines))
	for i, line := range lines {
		line = strings.ReplaceAll(line, " ", "\x00")
		line = expandTabs(line, 8)
		line = strings.ReplaceAll(line, " ", "\t")
		line = strings.ReplaceAll(line, "\x00", " ")
		out[i] = strings.TrimRight(line, "\n")
	}
	return out
}

func expandTabs(s string, tab int) string {
	var b strings.Builder
	col := 0
	for _, r := range s {
		switch r {
		case '\t':
			n := tab - col%tab
			b.WriteString(strings.Repeat(" ", n))
			col += n
		case '\n', '\r':
			b.WriteRune(r)
			col = 0
		default:
			b.WriteRune(r)
			col++
		}
	}
	return b.String()
}

const wrapColumn = 120

func numTruthy(v any) bool {
	switch x := v.(type) {
	case int:
		return x != 0
	case string:
		return x != ""
	}
	return v != nil
}

func splitLine(list *[]diffSide, num any, text string) {
	if !numTruthy(num) {
		*list = append(*list, diffSide{num, text})
		return
	}
	rs := []rune(text)
	size := len(rs)
	if size <= wrapColumn || size-strings.Count(text, "\x00")*3 <= wrapColumn {
		*list = append(*list, diffSide{num, text})
		return
	}
	i, n := 0, 0
	mark := ""
	for n < wrapColumn && i < size {
		switch rs[i] {
		case '\x00':
			i++
			mark = string(rs[i])
			i++
		case '\x01':
			i++
			mark = ""
		default:
			i++
			n++
		}
	}
	line1, line2 := string(rs[:i]), string(rs[i:])
	if mark != "" {
		line1 += "\x01"
		line2 = "\x00" + mark + line2
	}
	*list = append(*list, diffSide{num, line1})
	splitLine(list, ">", line2)
}

func lineWrapper(rows []diffRow) []diffRow {
	var out []diffRow
	for _, r := range rows {
		var f, t []diffSide
		splitLine(&f, r.from.num, r.from.text)
		splitLine(&t, r.to.num, r.to.text)
		for len(f) > 0 || len(t) > 0 {
			fd := diffSide{"", " "}
			td := diffSide{"", " "}
			if len(f) > 0 {
				fd, f = f[0], f[1:]
			}
			if len(t) > 0 {
				td, t = t[0], t[1:]
			}
			out = append(out, diffRow{&fd, &td, r.flag})
		}
	}
	return out
}

func formatLine(side int, num any, text string, prefix [2]string) string {
	id := ""
	numText := fmt.Sprint(num)
	if n, ok := num.(int); ok {
		id = fmt.Sprintf(` id="%s%d"`, prefix[side], n)
	}
	text = strings.NewReplacer("&", "&amp;", ">", "&gt;", "<", "&lt;").Replace(text)
	text = strings.TrimRightFunc(strings.ReplaceAll(text, " ", "&nbsp;"), unicode.IsSpace)
	return fmt.Sprintf(`<td class="diff_header"%s>%s</td><td nowrap="nowrap">%s</td>`, id, numText, text)
}

func collectLines(rows []diffRow, prefix [2]string) ([]string, []string, []*bool) {
	var fl, tl []string
	var flags []*bool
	for _, r := range rows {
		fl = append(fl, formatLine(0, r.from.num, r.from.text, prefix))
		tl = append(tl, formatLine(1, r.to.num, r.to.text, prefix))
		f := r.flag
		flags = append(flags, &f)
	}
	return fl, tl, flags
}

func convertFlags(fromList, toList *[]string, flags *[]*bool, toprefix string, numlines int) ([]string, []string) {
	n := len(*flags)
	nextID := make([]string, n)
	nextHref := make([]string, n)
	numChg, inChange, last := 0, false, 0
	for i, f := range *flags {
		if f != nil && *f {
			if !inChange {
				inChange = true
				last = i
				j := max(0, i-numlines)
				nextID[j] = fmt.Sprintf(` id="difflib_chg_%s_%d"`, toprefix, numChg)
				numChg++
				nextHref[last] = fmt.Sprintf(`<a href="#difflib_chg_%s_%d">n</a>`, toprefix, numChg)
			}
		} else {
			inChange = false
		}
	}
	if n == 0 {
		f := false
		*flags = []*bool{&f}
		nextID, nextHref = []string{""}, []string{""}
		last = 0
		*fromList = []string{`<td></td><td>&nbsp;Empty File&nbsp;</td>`}
		*toList = []string{`<td></td><td>&nbsp;Empty File&nbsp;</td>`}
	}
	if f := (*flags)[0]; f == nil || !*f {
		nextHref[0] = fmt.Sprintf(`<a href="#difflib_chg_%s_0">f</a>`, toprefix)
	}
	nextHref[last] = fmt.Sprintf(`<a href="#difflib_chg_%s_top">t</a>`, toprefix)
	return nextHref, nextID
}
