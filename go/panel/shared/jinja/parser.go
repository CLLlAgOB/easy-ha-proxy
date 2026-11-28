package jinja

import "strings"

// ---- AST ----

type node interface{}

type expr interface{}

type textNode struct{ text string }
type outputNode struct {
	e    expr
	line int
}
type ifNode struct {
	tests  []expr
	bodies [][]node
	els    []node
}
type forNode struct {
	target expr
	iter   expr
	cond   expr
	body   []node
	els    []node
	line   int
}
type setNode struct {
	target expr
	value  expr
	line   int
}
type setBlockNode struct {
	name    string
	filters []*filterExpr
	body    []node
}
type blockNode struct {
	name   string
	body   []node
	scoped bool
}
type extendsNode struct{ tmpl expr }
type includeNode struct {
	tmpl          expr
	ignoreMissing bool
	withContext   bool
}
type macroNode struct {
	name     string
	args     []string
	defaults []expr // aligned to the last len(defaults) args
	body     []node
}

// expressions
type constExpr struct{ v any }
type nameExpr struct {
	name string
	line int
}
type nsRefExpr struct{ name, attr string }
type getattrExpr struct {
	obj  expr
	attr string
}
type getitemExpr struct {
	obj expr
	arg expr
}
type sliceExpr struct{ start, stop, step expr }
type callExpr struct {
	fn     expr
	args   []expr
	kwargs []kwarg
	dyn    expr
	dynKw  expr
}
type kwarg struct {
	name string
	val  expr
}
type filterExpr struct {
	node   expr
	name   string
	args   []expr
	kwargs []kwarg
	dyn    expr
	dynKw  expr
	line   int
}
type testExpr struct {
	node   expr
	name   string
	args   []expr
	kwargs []kwarg
	negate bool
}
type binExpr struct {
	op   string
	l, r expr
}
type unaryExpr struct {
	op string
	e  expr
}
type compareExpr struct {
	first expr
	ops   []string
	rest  []expr
}
type andExpr struct{ l, r expr }
type orExpr struct{ l, r expr }
type notExpr struct{ e expr }
type condExpr struct{ test, a, b expr }
type listExpr struct{ items []expr }
type tupleExpr struct{ items []expr }
type dictExpr struct{ keys, vals []expr }
type concatExpr struct{ items []expr }

// Template is a parsed template.
type Template struct {
	Name   string
	body   []node
	blocks map[string]*blockNode
}

const maxParseDepth = 64

type parser struct {
	name   string
	toks   []token
	pos    int
	depth  int
	blocks map[string]*blockNode
}

func (p *parser) enterDepth() error {
	p.depth++
	if p.depth > maxParseDepth {
		p.depth--
		return p.errf("maximum template nesting depth (%d) exceeded", maxParseDepth)
	}
	return nil
}

func (p *parser) leaveDepth() {
	if p.depth > 0 {
		p.depth--
	}
}

func parse(name, src string) (*Template, error) { return parseWith(name, src, lexOpts{}) }

func parseWith(name, src string, o lexOpts) (*Template, error) {
	toks, err := lex(name, src, o)
	if err != nil {
		return nil, err
	}
	p := &parser{name: name, toks: toks, blocks: map[string]*blockNode{}}
	body, end, err := p.subparse(nil)
	if err != nil {
		return nil, err
	}
	if end != "" {
		return nil, p.errf("unexpected '%s'", end)
	}
	return &Template{Name: name, body: body, blocks: p.blocks}, nil
}

func (p *parser) cur() token  { return p.toks[p.pos] }
func (p *parser) peek() token { return p.toks[min(p.pos+1, len(p.toks)-1)] }
func (p *parser) next() token {
	t := p.toks[p.pos]
	if p.pos < len(p.toks)-1 {
		p.pos++
	}
	return t
}

func (p *parser) errf(format string, args ...any) error {
	return errf("%s:%d: "+format, append([]any{p.name, p.cur().line}, args...)...)
}

func (p *parser) expectOp(op string) error {
	if !p.cur().is(tOp, op) {
		return p.errf("expected '%s', got %q", op, p.cur().val)
	}
	p.next()
	return nil
}

func (p *parser) expectKind(k tokKind) (token, error) {
	if p.cur().kind != k {
		return token{}, p.errf("unexpected token %q", p.cur().val)
	}
	return p.next(), nil
}

func (p *parser) skipName(name string) bool {
	if p.cur().is(tName, name) {
		p.next()
		return true
	}
	return false
}

// subparse reads nodes until a block tag whose name is in ends; it returns the
// end tag's name with the parser positioned after that name.
func (p *parser) subparse(ends []string) ([]node, string, error) {
	if err := p.enterDepth(); err != nil {
		return nil, "", err
	}
	defer p.leaveDepth()
	var body []node
	for {
		t := p.cur()
		switch t.kind {
		case tEOF:
			if len(ends) > 0 {
				return nil, "", p.errf("unexpected end of template, expected %s", strings.Join(ends, "/"))
			}
			return body, "", nil
		case tData:
			p.next()
			body = append(body, &textNode{text: t.val})
		case tVarBegin:
			p.next()
			e, err := p.parseTuple(true, nil, false)
			if err != nil {
				return nil, "", err
			}
			if _, err := p.expectKind(tVarEnd); err != nil {
				return nil, "", err
			}
			body = append(body, &outputNode{e: e, line: t.line})
		case tBlockBegin:
			p.next()
			nameTok := p.cur()
			if nameTok.kind != tName {
				return nil, "", p.errf("tag name expected")
			}
			for _, e := range ends {
				if nameTok.val == e {
					p.next()
					return body, e, nil
				}
			}
			n, err := p.parseStatement()
			if err != nil {
				return nil, "", err
			}
			if n != nil {
				body = append(body, n)
			}
		default:
			return nil, "", p.errf("unexpected token %q", t.val)
		}
	}
}

func (p *parser) endTag() error {
	_, err := p.expectKind(tBlockEnd)
	return err
}

func (p *parser) parseStatement() (node, error) {
	t := p.next()
	switch t.val {
	case "if":
		return p.parseIf()
	case "for":
		return p.parseFor(t.line)
	case "set":
		return p.parseSet(t.line)
	case "block":
		return p.parseBlock()
	case "extends":
		e, err := p.parseExpression(true)
		if err != nil {
			return nil, err
		}
		return &extendsNode{tmpl: e}, p.endTag()
	case "include":
		return p.parseInclude()
	case "macro":
		return p.parseMacro()
	}
	return nil, p.errf("unknown tag '%s'", t.val)
}

func (p *parser) parseIf() (node, error) {
	n := &ifNode{}
	test, err := p.parseTuple(false, nil, false)
	if err != nil {
		return nil, err
	}
	if err := p.endTag(); err != nil {
		return nil, err
	}
	for {
		body, end, err := p.subparse([]string{"elif", "else", "endif"})
		if err != nil {
			return nil, err
		}
		n.tests = append(n.tests, test)
		n.bodies = append(n.bodies, body)
		switch end {
		case "elif":
			if test, err = p.parseTuple(false, nil, false); err != nil {
				return nil, err
			}
			if err := p.endTag(); err != nil {
				return nil, err
			}
			continue
		case "else":
			if err := p.endTag(); err != nil {
				return nil, err
			}
			els, _, err := p.subparse([]string{"endif"})
			if err != nil {
				return nil, err
			}
			n.els = els
		}
		return n, p.endTag()
	}
}

func (p *parser) parseFor(line int) (node, error) {
	target, err := p.parseAssignTarget([]string{"in"}, false)
	if err != nil {
		return nil, err
	}
	if !p.skipName("in") {
		return nil, p.errf("expected 'in'")
	}
	iter, err := p.parseTuple(false, []string{"recursive"}, false)
	if err != nil {
		return nil, err
	}
	n := &forNode{target: target, iter: iter, line: line}
	if p.skipName("if") {
		if n.cond, err = p.parseExpression(true); err != nil {
			return nil, err
		}
	}
	if p.skipName("recursive") {
		return nil, p.errf("recursive loops are not supported")
	}
	if err := p.endTag(); err != nil {
		return nil, err
	}
	body, end, err := p.subparse([]string{"endfor", "else"})
	if err != nil {
		return nil, err
	}
	n.body = body
	if end == "else" {
		if err := p.endTag(); err != nil {
			return nil, err
		}
		if n.els, _, err = p.subparse([]string{"endfor"}); err != nil {
			return nil, err
		}
	}
	return n, p.endTag()
}

func (p *parser) parseSet(line int) (node, error) {
	target, err := p.parseAssignTarget(nil, true)
	if err != nil {
		return nil, err
	}
	if p.cur().is(tOp, "=") {
		p.next()
		value, err := p.parseTuple(true, nil, false)
		if err != nil {
			return nil, err
		}
		return &setNode{target: target, value: value, line: line}, p.endTag()
	}
	ne, ok := target.(*nameExpr)
	if !ok {
		return nil, p.errf("block set needs a plain name")
	}
	n := &setBlockNode{name: ne.name}
	for p.cur().is(tOp, "|") {
		f, err := p.parseFilter(nil, true)
		if err != nil {
			return nil, err
		}
		n.filters = append(n.filters, f)
	}
	if err := p.endTag(); err != nil {
		return nil, err
	}
	body, _, err := p.subparse([]string{"endset"})
	if err != nil {
		return nil, err
	}
	n.body = body
	return n, p.endTag()
}

func (p *parser) parseBlock() (node, error) {
	nameTok, err := p.expectKind(tName)
	if err != nil {
		return nil, err
	}
	n := &blockNode{name: nameTok.val}
	if p.skipName("scoped") {
		n.scoped = true
	}
	p.skipName("required")
	if err := p.endTag(); err != nil {
		return nil, err
	}
	body, _, err := p.subparse([]string{"endblock"})
	if err != nil {
		return nil, err
	}
	n.body = body
	if p.cur().kind == tName {
		p.next()
	}
	if _, dup := p.blocks[n.name]; dup {
		return nil, p.errf("block '%s' defined twice", n.name)
	}
	p.blocks[n.name] = n
	return n, p.endTag()
}

func (p *parser) parseInclude() (node, error) {
	e, err := p.parseExpression(true)
	if err != nil {
		return nil, err
	}
	n := &includeNode{tmpl: e, withContext: true}
	if p.cur().is(tName, "ignore") && p.peek().is(tName, "missing") {
		p.next()
		p.next()
		n.ignoreMissing = true
	}
	if p.cur().is(tName, "with") || p.cur().is(tName, "without") {
		n.withContext = p.next().val == "with"
		if !p.skipName("context") {
			return nil, p.errf("expected 'context'")
		}
	}
	return n, p.endTag()
}

func (p *parser) parseMacro() (node, error) {
	nameTok, err := p.expectKind(tName)
	if err != nil {
		return nil, err
	}
	n := &macroNode{name: nameTok.val}
	if err := p.expectOp("("); err != nil {
		return nil, err
	}
	for !p.cur().is(tOp, ")") {
		if len(n.args) > 0 {
			if err := p.expectOp(","); err != nil {
				return nil, err
			}
			if p.cur().is(tOp, ")") {
				break
			}
		}
		arg, err := p.expectKind(tName)
		if err != nil {
			return nil, err
		}
		n.args = append(n.args, arg.val)
		if p.cur().is(tOp, "=") {
			p.next()
			d, err := p.parseExpression(true)
			if err != nil {
				return nil, err
			}
			n.defaults = append(n.defaults, d)
		} else if len(n.defaults) > 0 {
			return nil, p.errf("non-default argument follows default argument")
		}
	}
	p.next()
	if err := p.endTag(); err != nil {
		return nil, err
	}
	body, _, err := p.subparse([]string{"endmacro"})
	if err != nil {
		return nil, err
	}
	n.body = body
	return n, p.endTag()
}

func (p *parser) parseAssignTarget(extraEnd []string, withNamespace bool) (expr, error) {
	if withNamespace && p.cur().kind == tName && p.peek().is(tOp, ".") {
		ns := p.next().val
		p.next()
		attr, err := p.expectKind(tName)
		if err != nil {
			return nil, err
		}
		return &nsRefExpr{name: ns, attr: attr.val}, nil
	}
	var items []expr
	for {
		if len(items) > 0 {
			if !p.cur().is(tOp, ",") {
				break
			}
			p.next()
		}
		if p.cur().kind != tName || p.isEnd(extraEnd) {
			if len(items) == 0 {
				return nil, p.errf("can't assign to %q", p.cur().val)
			}
			break
		}
		t := p.next()
		items = append(items, &nameExpr{name: t.val, line: t.line})
	}
	if len(items) == 1 && !p.toks[p.pos-1].is(tOp, ",") {
		return items[0], nil
	}
	return &tupleExpr{items: items}, nil
}

func (p *parser) isEnd(extra []string) bool {
	t := p.cur()
	if t.kind == tVarEnd || t.kind == tBlockEnd || t.kind == tEOF {
		return true
	}
	for _, e := range extra {
		if t.is(tName, e) {
			return true
		}
	}
	return false
}

// parseTuple mirrors Parser.parse_tuple.
func (p *parser) parseTuple(withCondexpr bool, extraEnd []string, explicitParens bool) (expr, error) {
	parseOne := func() (expr, error) {
		if withCondexpr {
			return p.parseExpression(true)
		}
		return p.parseOr()
	}
	var items []expr
	isTuple := false
	for {
		if len(items) > 0 {
			if !p.cur().is(tOp, ",") {
				break
			}
			p.next()
			isTuple = true
		}
		if p.isEnd(extraEnd) || (explicitParens && p.cur().is(tOp, ")")) {
			break
		}
		e, err := parseOne()
		if err != nil {
			return nil, err
		}
		items = append(items, e)
	}
	if !isTuple {
		if len(items) == 1 {
			return items[0], nil
		}
		if !explicitParens {
			return nil, p.errf("expected an expression, got %q", p.cur().val)
		}
	}
	return &tupleExpr{items: items}, nil
}

func (p *parser) parseExpression(withCondexpr bool) (expr, error) {
	if err := p.enterDepth(); err != nil {
		return nil, err
	}
	defer p.leaveDepth()
	if withCondexpr {
		return p.parseCondexpr()
	}
	return p.parseOr()
}

func (p *parser) parseCondexpr() (expr, error) {
	e, err := p.parseOr()
	if err != nil {
		return nil, err
	}
	for p.skipName("if") {
		test, err := p.parseOr()
		if err != nil {
			return nil, err
		}
		var b expr
		if p.skipName("else") {
			if b, err = p.parseCondexpr(); err != nil {
				return nil, err
			}
		}
		e = &condExpr{test: test, a: e, b: b}
	}
	return e, nil
}

func (p *parser) parseOr() (expr, error) {
	l, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	for p.skipName("or") {
		r, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		l = &orExpr{l: l, r: r}
	}
	return l, nil
}

func (p *parser) parseAnd() (expr, error) {
	l, err := p.parseNot()
	if err != nil {
		return nil, err
	}
	for p.skipName("and") {
		r, err := p.parseNot()
		if err != nil {
			return nil, err
		}
		l = &andExpr{l: l, r: r}
	}
	return l, nil
}

func (p *parser) parseNot() (expr, error) {
	if p.skipName("not") {
		e, err := p.parseNot()
		if err != nil {
			return nil, err
		}
		return &notExpr{e: e}, nil
	}
	return p.parseCompare()
}

func (p *parser) parseCompare() (expr, error) {
	first, err := p.parseMath1()
	if err != nil {
		return nil, err
	}
	c := &compareExpr{first: first}
	for {
		t := p.cur()
		var op string
		switch {
		case t.kind == tOp && (t.val == "==" || t.val == "!=" || t.val == "<" || t.val == ">" || t.val == "<=" || t.val == ">="):
			op = t.val
			p.next()
		case t.is(tName, "in"):
			op = "in"
			p.next()
		case t.is(tName, "not") && p.peek().is(tName, "in"):
			op = "notin"
			p.next()
			p.next()
		default:
			if len(c.ops) == 0 {
				return first, nil
			}
			return c, nil
		}
		r, err := p.parseMath1()
		if err != nil {
			return nil, err
		}
		c.ops = append(c.ops, op)
		c.rest = append(c.rest, r)
	}
}

func (p *parser) parseMath1() (expr, error) {
	l, err := p.parseConcat()
	if err != nil {
		return nil, err
	}
	for p.cur().is(tOp, "+") || p.cur().is(tOp, "-") {
		op := p.next().val
		r, err := p.parseConcat()
		if err != nil {
			return nil, err
		}
		l = &binExpr{op: op, l: l, r: r}
	}
	return l, nil
}

func (p *parser) parseConcat() (expr, error) {
	first, err := p.parseMath2()
	if err != nil {
		return nil, err
	}
	items := []expr{first}
	for p.cur().is(tOp, "~") {
		p.next()
		r, err := p.parseMath2()
		if err != nil {
			return nil, err
		}
		items = append(items, r)
	}
	if len(items) == 1 {
		return first, nil
	}
	return &concatExpr{items: items}, nil
}

func (p *parser) parseMath2() (expr, error) {
	l, err := p.parsePow()
	if err != nil {
		return nil, err
	}
	for {
		t := p.cur()
		if t.kind == tOp && (t.val == "*" || t.val == "/" || t.val == "//" || t.val == "%") {
			p.next()
			r, err := p.parsePow()
			if err != nil {
				return nil, err
			}
			l = &binExpr{op: t.val, l: l, r: r}
			continue
		}
		return l, nil
	}
}

func (p *parser) parsePow() (expr, error) {
	l, err := p.parseUnary(true)
	if err != nil {
		return nil, err
	}
	for p.cur().is(tOp, "**") {
		p.next()
		r, err := p.parseUnary(true)
		if err != nil {
			return nil, err
		}
		l = &binExpr{op: "**", l: l, r: r}
	}
	return l, nil
}

func (p *parser) parseUnary(withFilter bool) (expr, error) {
	var e expr
	var err error
	switch {
	case p.cur().is(tOp, "-"):
		p.next()
		inner, err := p.parseUnary(false)
		if err != nil {
			return nil, err
		}
		e = &unaryExpr{op: "-", e: inner}
	case p.cur().is(tOp, "+"):
		p.next()
		inner, err := p.parseUnary(false)
		if err != nil {
			return nil, err
		}
		e = &unaryExpr{op: "+", e: inner}
	default:
		if e, err = p.parsePrimary(); err != nil {
			return nil, err
		}
	}
	if e, err = p.parsePostfix(e); err != nil {
		return nil, err
	}
	if withFilter {
		return p.parseFilterExpr(e)
	}
	return e, nil
}

func (p *parser) parsePrimary() (expr, error) {
	t := p.cur()
	switch t.kind {
	case tName:
		p.next()
		switch t.val {
		case "true", "True":
			return &constExpr{v: true}, nil
		case "false", "False":
			return &constExpr{v: false}, nil
		case "none", "None":
			return &constExpr{v: nil}, nil
		}
		return &nameExpr{name: t.val, line: t.line}, nil
	case tString:
		p.next()
		s := t.val
		for p.cur().kind == tString {
			s += p.next().val
		}
		return &constExpr{v: s}, nil
	case tInt, tFloat:
		p.next()
		return &constExpr{v: t.num}, nil
	case tOp:
		switch t.val {
		case "(":
			p.next()
			e, err := p.parseTuple(true, nil, true)
			if err != nil {
				return nil, err
			}
			return e, p.expectOp(")")
		case "[":
			p.next()
			l := &listExpr{}
			for !p.cur().is(tOp, "]") {
				if len(l.items) > 0 {
					if err := p.expectOp(","); err != nil {
						return nil, err
					}
					if p.cur().is(tOp, "]") {
						break
					}
				}
				e, err := p.parseExpression(true)
				if err != nil {
					return nil, err
				}
				l.items = append(l.items, e)
			}
			p.next()
			return l, nil
		case "{":
			p.next()
			d := &dictExpr{}
			for !p.cur().is(tOp, "}") {
				if len(d.keys) > 0 {
					if err := p.expectOp(","); err != nil {
						return nil, err
					}
					if p.cur().is(tOp, "}") {
						break
					}
				}
				k, err := p.parseExpression(true)
				if err != nil {
					return nil, err
				}
				if err := p.expectOp(":"); err != nil {
					return nil, err
				}
				v, err := p.parseExpression(true)
				if err != nil {
					return nil, err
				}
				d.keys = append(d.keys, k)
				d.vals = append(d.vals, v)
			}
			p.next()
			return d, nil
		}
	}
	return nil, p.errf("unexpected %q", t.val)
}

func (p *parser) parsePostfix(e expr) (expr, error) {
	for {
		t := p.cur()
		switch {
		case t.is(tOp, ".") || t.is(tOp, "["):
			var err error
			if e, err = p.parseSubscript(e); err != nil {
				return nil, err
			}
		case t.is(tOp, "("):
			var err error
			if e, err = p.parseCall(e); err != nil {
				return nil, err
			}
		default:
			return e, nil
		}
	}
}

func (p *parser) parseFilterExpr(e expr) (expr, error) {
	for {
		t := p.cur()
		switch {
		case t.is(tOp, "|"):
			f, err := p.parseFilter(e, false)
			if err != nil {
				return nil, err
			}
			e = f
		case t.is(tName, "is"):
			te, err := p.parseTest(e)
			if err != nil {
				return nil, err
			}
			e = te
		case t.is(tOp, "("):
			var err error
			if e, err = p.parseCall(e); err != nil {
				return nil, err
			}
		default:
			return e, nil
		}
	}
}

func (p *parser) parseSubscript(e expr) (expr, error) {
	t := p.next()
	if t.val == "." {
		a := p.next()
		switch a.kind {
		case tName:
			return &getattrExpr{obj: e, attr: a.val}, nil
		case tInt:
			return &getitemExpr{obj: e, arg: &constExpr{v: a.num}}, nil
		}
		return nil, p.errf("expected name or number")
	}
	var args []expr
	for !p.cur().is(tOp, "]") {
		if len(args) > 0 {
			if err := p.expectOp(","); err != nil {
				return nil, err
			}
		}
		a, err := p.parseSubscribed()
		if err != nil {
			return nil, err
		}
		args = append(args, a)
	}
	p.next()
	if len(args) == 1 {
		return &getitemExpr{obj: e, arg: args[0]}, nil
	}
	return &getitemExpr{obj: e, arg: &tupleExpr{items: args}}, nil
}

func (p *parser) parseSubscribed() (expr, error) {
	var parts [3]expr
	var err error
	if p.cur().is(tOp, ":") {
		p.next()
	} else {
		first, err := p.parseExpression(true)
		if err != nil {
			return nil, err
		}
		if !p.cur().is(tOp, ":") {
			return first, nil
		}
		p.next()
		parts[0] = first
	}
	if !p.cur().is(tOp, "]") && !p.cur().is(tOp, ",") && !p.cur().is(tOp, ":") {
		if parts[1], err = p.parseExpression(true); err != nil {
			return nil, err
		}
	}
	if p.cur().is(tOp, ":") {
		p.next()
		if !p.cur().is(tOp, "]") && !p.cur().is(tOp, ",") {
			if parts[2], err = p.parseExpression(true); err != nil {
				return nil, err
			}
		}
	}
	return &sliceExpr{start: parts[0], stop: parts[1], step: parts[2]}, nil
}

func (p *parser) parseCallArgs() ([]expr, []kwarg, expr, expr, error) {
	if err := p.expectOp("("); err != nil {
		return nil, nil, nil, nil, err
	}
	var args []expr
	var kwargs []kwarg
	var dyn, dynKw expr
	first := true
	for !p.cur().is(tOp, ")") {
		if !first {
			if err := p.expectOp(","); err != nil {
				return nil, nil, nil, nil, err
			}
			if p.cur().is(tOp, ")") {
				break
			}
		}
		first = false
		switch {
		case p.cur().is(tOp, "*"):
			p.next()
			e, err := p.parseExpression(true)
			if err != nil {
				return nil, nil, nil, nil, err
			}
			dyn = e
		case p.cur().is(tOp, "**"):
			p.next()
			e, err := p.parseExpression(true)
			if err != nil {
				return nil, nil, nil, nil, err
			}
			dynKw = e
		case p.cur().kind == tName && p.peek().is(tOp, "="):
			k := p.next().val
			p.next()
			e, err := p.parseExpression(true)
			if err != nil {
				return nil, nil, nil, nil, err
			}
			kwargs = append(kwargs, kwarg{name: k, val: e})
		default:
			e, err := p.parseExpression(true)
			if err != nil {
				return nil, nil, nil, nil, err
			}
			args = append(args, e)
		}
	}
	p.next()
	return args, kwargs, dyn, dynKw, nil
}

func (p *parser) parseCall(e expr) (expr, error) {
	args, kwargs, dyn, dynKw, err := p.parseCallArgs()
	if err != nil {
		return nil, err
	}
	return &callExpr{fn: e, args: args, kwargs: kwargs, dyn: dyn, dynKw: dynKw}, nil
}

func (p *parser) parseFilter(e expr, startInline bool) (*filterExpr, error) {
	_ = startInline
	line := p.next().line // '|'
	nameTok, err := p.expectKind(tName)
	if err != nil {
		return nil, err
	}
	name := nameTok.val
	for p.cur().is(tOp, ".") {
		p.next()
		n, err := p.expectKind(tName)
		if err != nil {
			return nil, err
		}
		name += "." + n.val
	}
	f := &filterExpr{node: e, name: name, line: line}
	if p.cur().is(tOp, "(") {
		if f.args, f.kwargs, f.dyn, f.dynKw, err = p.parseCallArgs(); err != nil {
			return nil, err
		}
	}
	return f, nil
}

func (p *parser) parseTest(e expr) (expr, error) {
	p.next() // 'is'
	negate := p.skipName("not")
	nameTok, err := p.expectKind(tName)
	if err != nil {
		return nil, err
	}
	name := nameTok.val
	for p.cur().is(tOp, ".") {
		p.next()
		n, err := p.expectKind(tName)
		if err != nil {
			return nil, err
		}
		name += "." + n.val
	}
	t := &testExpr{node: e, name: name, negate: negate}
	cur := p.cur()
	switch {
	case cur.is(tOp, "("):
		if t.args, t.kwargs, _, _, err = p.parseCallArgs(); err != nil {
			return nil, err
		}
	case (cur.kind == tName && cur.val != "else" && cur.val != "or" && cur.val != "and") ||
		cur.kind == tString || cur.kind == tInt || cur.kind == tFloat ||
		cur.is(tOp, "[") || cur.is(tOp, "{") || cur.is(tOp, "("):
		if cur.is(tName, "is") {
			return nil, p.errf("You cannot chain multiple tests with is")
		}
		arg, err := p.parsePrimary()
		if err != nil {
			return nil, err
		}
		if arg, err = p.parsePostfix(arg); err != nil {
			return nil, err
		}
		t.args = []expr{arg}
	}
	return t, nil
}
