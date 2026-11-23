package app

// Port of the parts of CPython 3.12 difflib that HtmlDiff.make_table uses
// (SequenceMatcher, Differ's fancy replace, _mdiff and HtmlDiff), so the
// configuration diff renders as the Flask panel's does.

import (
	"sort"
	"strings"
)

// ---- SequenceMatcher over comparable sequences ----

type match struct{ a, b, size int }

type opcode struct {
	tag            string
	i1, i2, j1, j2 int
}

type seqMatcher struct {
	a, b     []string
	isJunk   func(string) bool
	b2j      map[string][]int
	bjunk    map[string]bool
	bpopular map[string]bool
	matching []match
	opcodes  []opcode
	fullbcnt map[string]int
	autojunk bool
}

func newSeqMatcher(isJunk func(string) bool, a, b []string, autojunk bool) *seqMatcher {
	s := &seqMatcher{isJunk: isJunk, autojunk: autojunk}
	s.setSeqs(a, b)
	return s
}

func (s *seqMatcher) setSeqs(a, b []string) {
	s.a = a
	s.setSeq2(b)
}

func (s *seqMatcher) setSeq1(a []string) {
	s.a = a
	s.matching, s.opcodes = nil, nil
}

func (s *seqMatcher) setSeq2(b []string) {
	s.b = b
	s.matching, s.opcodes, s.fullbcnt = nil, nil, nil
	s.chainB()
}

func (s *seqMatcher) chainB() {
	b := s.b
	s.b2j = map[string][]int{}
	for i, elt := range b {
		s.b2j[elt] = append(s.b2j[elt], i)
	}
	s.bjunk = map[string]bool{}
	if s.isJunk != nil {
		for elt := range s.b2j {
			if s.isJunk(elt) {
				s.bjunk[elt] = true
			}
		}
		for elt := range s.bjunk {
			delete(s.b2j, elt)
		}
	}
	s.bpopular = map[string]bool{}
	n := len(b)
	if s.autojunk && n >= 200 {
		ntest := n/100 + 1
		for elt, idxs := range s.b2j {
			if len(idxs) > ntest {
				s.bpopular[elt] = true
			}
		}
		for elt := range s.bpopular {
			delete(s.b2j, elt)
		}
	}
}

func (s *seqMatcher) findLongestMatch(alo, ahi, blo, bhi int) match {
	a, b, b2j, isbjunk := s.a, s.b, s.b2j, s.bjunk
	besti, bestj, bestsize := alo, blo, 0
	j2len := map[int]int{}
	for i := alo; i < ahi; i++ {
		newj2len := map[int]int{}
		for _, j := range b2j[a[i]] {
			if j < blo {
				continue
			}
			if j >= bhi {
				break
			}
			k := j2len[j-1] + 1
			newj2len[j] = k
			if k > bestsize {
				besti, bestj, bestsize = i-k+1, j-k+1, k
			}
		}
		j2len = newj2len
	}
	for besti > alo && bestj > blo && !isbjunk[b[bestj-1]] && a[besti-1] == b[bestj-1] {
		besti, bestj, bestsize = besti-1, bestj-1, bestsize+1
	}
	for besti+bestsize < ahi && bestj+bestsize < bhi && !isbjunk[b[bestj+bestsize]] && a[besti+bestsize] == b[bestj+bestsize] {
		bestsize++
	}
	for besti > alo && bestj > blo && isbjunk[b[bestj-1]] && a[besti-1] == b[bestj-1] {
		besti, bestj, bestsize = besti-1, bestj-1, bestsize+1
	}
	for besti+bestsize < ahi && bestj+bestsize < bhi && isbjunk[b[bestj+bestsize]] && a[besti+bestsize] == b[bestj+bestsize] {
		bestsize++
	}
	return match{besti, bestj, bestsize}
}

func (s *seqMatcher) matchingBlocks() []match {
	if s.matching != nil {
		return s.matching
	}
	la, lb := len(s.a), len(s.b)
	type q struct{ alo, ahi, blo, bhi int }
	queue := []q{{0, la, 0, lb}}
	var blocks []match
	for len(queue) > 0 {
		x := queue[len(queue)-1]
		queue = queue[:len(queue)-1]
		m := s.findLongestMatch(x.alo, x.ahi, x.blo, x.bhi)
		if m.size > 0 {
			blocks = append(blocks, m)
			if x.alo < m.a && x.blo < m.b {
				queue = append(queue, q{x.alo, m.a, x.blo, m.b})
			}
			if m.a+m.size < x.ahi && m.b+m.size < x.bhi {
				queue = append(queue, q{m.a + m.size, x.ahi, m.b + m.size, x.bhi})
			}
		}
	}
	sort.Slice(blocks, func(i, j int) bool {
		if blocks[i].a != blocks[j].a {
			return blocks[i].a < blocks[j].a
		}
		if blocks[i].b != blocks[j].b {
			return blocks[i].b < blocks[j].b
		}
		return blocks[i].size < blocks[j].size
	})
	i1, j1, k1 := 0, 0, 0
	var nonAdj []match
	for _, m := range blocks {
		if i1+k1 == m.a && j1+k1 == m.b {
			k1 += m.size
		} else {
			if k1 > 0 {
				nonAdj = append(nonAdj, match{i1, j1, k1})
			}
			i1, j1, k1 = m.a, m.b, m.size
		}
	}
	if k1 > 0 {
		nonAdj = append(nonAdj, match{i1, j1, k1})
	}
	nonAdj = append(nonAdj, match{la, lb, 0})
	s.matching = nonAdj
	return s.matching
}

func (s *seqMatcher) getOpcodes() []opcode {
	if s.opcodes != nil {
		return s.opcodes
	}
	i, j := 0, 0
	var ops []opcode
	for _, m := range s.matchingBlocks() {
		tag := ""
		if i < m.a && j < m.b {
			tag = "replace"
		} else if i < m.a {
			tag = "delete"
		} else if j < m.b {
			tag = "insert"
		}
		if tag != "" {
			ops = append(ops, opcode{tag, i, m.a, j, m.b})
		}
		i, j = m.a+m.size, m.b+m.size
		if m.size > 0 {
			ops = append(ops, opcode{"equal", m.a, i, m.b, j})
		}
	}
	s.opcodes = ops
	return ops
}

func calcRatio(matches, length int) float64 {
	if length > 0 {
		return 2.0 * float64(matches) / float64(length)
	}
	return 1.0
}

func (s *seqMatcher) ratio() float64 {
	m := 0
	for _, b := range s.matchingBlocks() {
		m += b.size
	}
	return calcRatio(m, len(s.a)+len(s.b))
}

func (s *seqMatcher) quickRatio() float64 {
	if s.fullbcnt == nil {
		s.fullbcnt = map[string]int{}
		for _, elt := range s.b {
			s.fullbcnt[elt]++
		}
	}
	avail := map[string]int{}
	matches := 0
	for _, elt := range s.a {
		numb, ok := avail[elt]
		if !ok {
			numb = s.fullbcnt[elt]
		}
		avail[elt] = numb - 1
		if numb > 0 {
			matches++
		}
	}
	return calcRatio(matches, len(s.a)+len(s.b))
}

func (s *seqMatcher) realQuickRatio() float64 {
	la, lb := len(s.a), len(s.b)
	return calcRatio(min(la, lb), la+lb)
}

// ---- Differ (ndiff with fancy replace) ----

func isCharacterJunk(ch string) bool { return ch == " " || ch == "\t" }

func chars(s string) []string {
	out := make([]string, 0, len(s))
	for _, r := range s {
		out = append(out, string(r))
	}
	return out
}

type differ struct {
	charjunk func(string) bool
}

func (d *differ) compare(a, b []string) []string {
	cruncher := newSeqMatcher(nil, a, b, true)
	var out []string
	for _, op := range cruncher.getOpcodes() {
		switch op.tag {
		case "replace":
			out = append(out, d.fancyReplace(a, op.i1, op.i2, b, op.j1, op.j2)...)
		case "delete":
			out = append(out, d.dump("-", a, op.i1, op.i2)...)
		case "insert":
			out = append(out, d.dump("+", b, op.j1, op.j2)...)
		case "equal":
			out = append(out, d.dump(" ", a, op.i1, op.i2)...)
		}
	}
	return out
}

func (d *differ) dump(tag string, x []string, lo, hi int) []string {
	out := make([]string, 0, hi-lo)
	for i := lo; i < hi; i++ {
		out = append(out, tag+" "+x[i])
	}
	return out
}

func (d *differ) plainReplace(a []string, alo, ahi int, b []string, blo, bhi int) []string {
	var first, second []string
	if bhi-blo < ahi-alo {
		first = d.dump("+", b, blo, bhi)
		second = d.dump("-", a, alo, ahi)
	} else {
		first = d.dump("-", a, alo, ahi)
		second = d.dump("+", b, blo, bhi)
	}
	return append(first, second...)
}

func (d *differ) fancyReplace(a []string, alo, ahi int, b []string, blo, bhi int) []string {
	bestRatio, cutoff := 0.74, 0.75
	cruncher := newSeqMatcher(d.charjunk, nil, nil, true)
	eqi, eqj := -1, -1
	besti, bestj := 0, 0
	for j := blo; j < bhi; j++ {
		bj := b[j]
		cruncher.setSeq2(chars(bj))
		for i := alo; i < ahi; i++ {
			ai := a[i]
			if ai == bj {
				if eqi < 0 {
					eqi, eqj = i, j
				}
				continue
			}
			cruncher.setSeq1(chars(ai))
			if cruncher.realQuickRatio() > bestRatio && cruncher.quickRatio() > bestRatio && cruncher.ratio() > bestRatio {
				bestRatio, besti, bestj = cruncher.ratio(), i, j
			}
		}
	}
	if bestRatio < cutoff {
		if eqi < 0 {
			return d.plainReplace(a, alo, ahi, b, blo, bhi)
		}
		besti, bestj, bestRatio = eqi, eqj, 1.0
	} else {
		eqi = -1
	}
	var out []string
	out = append(out, d.fancyHelper(a, alo, besti, b, blo, bestj)...)
	aelt, belt := a[besti], b[bestj]
	if eqi < 0 {
		var atags, btags strings.Builder
		cruncher.setSeqs(chars(aelt), chars(belt))
		for _, op := range cruncher.getOpcodes() {
			la, lb := op.i2-op.i1, op.j2-op.j1
			switch op.tag {
			case "replace":
				atags.WriteString(strings.Repeat("^", la))
				btags.WriteString(strings.Repeat("^", lb))
			case "delete":
				atags.WriteString(strings.Repeat("-", la))
			case "insert":
				btags.WriteString(strings.Repeat("+", lb))
			case "equal":
				atags.WriteString(strings.Repeat(" ", la))
				btags.WriteString(strings.Repeat(" ", lb))
			}
		}
		out = append(out, d.qformat(aelt, belt, atags.String(), btags.String())...)
	} else {
		out = append(out, "  "+aelt)
	}
	out = append(out, d.fancyHelper(a, besti+1, ahi, b, bestj+1, bhi)...)
	return out
}

func (d *differ) fancyHelper(a []string, alo, ahi int, b []string, blo, bhi int) []string {
	if alo < ahi {
		if blo < bhi {
			return d.fancyReplace(a, alo, ahi, b, blo, bhi)
		}
		return d.dump("-", a, alo, ahi)
	} else if blo < bhi {
		return d.dump("+", b, blo, bhi)
	}
	return nil
}

func keepOriginalWS(s, tags string) string {
	sr := []rune(s)
	var b strings.Builder
	for i, t := range tags {
		if i >= len(sr) {
			break
		}
		if t == ' ' && (sr[i] == ' ' || sr[i] == '\t') {
			b.WriteRune(sr[i])
		} else {
			b.WriteRune(t)
		}
	}
	return b.String()
}

func (d *differ) qformat(aline, bline, atags, btags string) []string {
	atags = strings.TrimRight(keepOriginalWS(aline, atags), " \t\n\r\x0b\x0c")
	btags = strings.TrimRight(keepOriginalWS(bline, btags), " \t\n\r\x0b\x0c")
	out := []string{"- " + aline}
	if atags != "" {
		out = append(out, "? "+atags+"\n")
	}
	out = append(out, "+ "+bline)
	if btags != "" {
		out = append(out, "? "+btags+"\n")
	}
	return out
}
