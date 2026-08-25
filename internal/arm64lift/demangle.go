package arm64lift

import "strings"

// itaniumDemangle parses an Itanium C++ ABI mangled name (the "_Z..."
// form every AArch64 Android/Linux C++ toolchain uses) and renders its
// qualified NAME - namespace/class path plus resolved template
// arguments, e.g. "std::__ndk1::basic_string<char, ...>::find" - or,
// for a vtable/typeinfo/thunk special-name, a short descriptive label
// matching c++filt's own phrasing ("vtable for X", ...).
//
// Deliberately stops at the end of <name> and never parses the
// trailing <bare-function-type> (the parameter type list): a
// substitution reference can only ever point BACKWARD to something
// already encoded earlier in the same string, so everything needed to
// correctly resolve every substitution that could possibly appear
// within <name> is fully available without looking at what follows it
// - and the caller (buildCall) only ever wants the bare name, since
// the real argument list is rendered separately from the lifted
// call's own args. This also keeps the grammar subset actually needed
// far smaller than a full demangler would require.
//
// Returns ok=false on ANY unrecognized or malformed construct,
// matching this project's existing "never render something silently
// wrong" philosophy for demangling - callers fall back to the raw
// mangled name unchanged.
// Demangle renders a possibly Itanium-mangled symbol down to its
// bare, readable qualified name (see itaniumDemangle), falling back to
// the name unchanged when it isn't mangled or isn't recognized.
// Exported for callers outside this package that display a raw
// resolved symbol name (e.g. pipeline's own per-function header
// comment) - buildCall itself uses the unexported demangle directly.
func Demangle(name string) string {
	return demangle(name)
}

func itaniumDemangle(mangled string) (string, bool) {
	if !strings.HasPrefix(mangled, "_Z") {
		return "", false
	}
	d := &demangler{s: mangled[2:]}
	name, ok := d.parseTopLevel()
	if !ok || name == "" {
		return "", false
	}
	return name, true
}

type demangler struct {
	s    string
	subs []string
	// templateArgStack holds the innermost currently-active template-
	// argument list(s) still in scope, for resolving T_/T0_/...
	// template-parameter back-references (a member that re-mentions
	// its own enclosing class template's parameters). An
	// approximation of the full Itanium scope rules (which track
	// multiple simultaneously-visible parameter lists more
	// precisely), but matches real-world compiler output for the
	// common case of a template's own member referencing that same
	// template's immediate parameters.
	templateArgStack [][]string
}

func (d *demangler) peek() byte {
	if len(d.s) == 0 {
		return 0
	}
	return d.s[0]
}

func (d *demangler) take(n int) string {
	if n > len(d.s) {
		n = len(d.s)
	}
	v := d.s[:n]
	d.s = d.s[n:]
	return v
}

func (d *demangler) eat(c byte) bool {
	if d.peek() != c {
		return false
	}
	d.s = d.s[1:]
	return true
}

func (d *demangler) eatStr(s string) bool {
	if !strings.HasPrefix(d.s, s) {
		return false
	}
	d.s = d.s[len(s):]
	return true
}

// addSub records a newly-completed substitutable component.
func (d *demangler) addSub(s string) {
	d.subs = append(d.subs, s)
}

// parseTopLevel handles <encoding> | <special-name>, stopping after
// <name> (see itaniumDemangle's own doc comment).
func (d *demangler) parseTopLevel() (string, bool) {
	switch {
	case d.eatStr("TV"):
		t, ok := d.parseType()
		return "vtable for " + t, ok
	case d.eatStr("TT"):
		t, ok := d.parseType()
		return "VTT for " + t, ok
	case d.eatStr("TI"):
		t, ok := d.parseType()
		return "typeinfo for " + t, ok
	case d.eatStr("TS"):
		t, ok := d.parseType()
		return "typeinfo name for " + t, ok
	case d.eatStr("GV"):
		n, ok := d.parseName()
		return "guard variable for " + n, ok
	case d.eatStr("GR"):
		n, ok := d.parseName()
		return "reference temporary for " + n, ok
	case d.peek() == 'T':
		return d.parseThunk()
	}
	return d.parseName()
}

// parseThunk handles "T <call-offset> <encoding>" (non-virtual/virtual
// thunk) and "Tc <call-offset> <call-offset> <encoding>" (covariant
// return thunk) - the offsets themselves aren't part of a readable
// name, just consumed to reach the underlying function's own name.
func (d *demangler) parseThunk() (string, bool) {
	covariant := d.eatStr("Tc")
	if !covariant && !d.eat('T') {
		return "", false
	}
	label := "non-virtual thunk to "
	if !d.parseCallOffset() {
		return "", false
	}
	if d.peek() == 'h' || d.peek() == 'v' {
		label = "virtual thunk to "
	}
	if covariant {
		if !d.parseCallOffset() {
			return "", false
		}
		label = "covariant return thunk to "
	}
	name, ok := d.parseName()
	return label + name, ok
}

// parseCallOffset consumes "h <number> _" or "v <number> _ <number> _".
func (d *demangler) parseCallOffset() bool {
	switch {
	case d.eat('h'):
		_, ok := d.parseSignedNumber()
		return ok && d.eat('_')
	case d.eat('v'):
		if _, ok := d.parseSignedNumber(); !ok || !d.eat('_') {
			return false
		}
		_, ok := d.parseSignedNumber()
		return ok && d.eat('_')
	}
	return false
}

func (d *demangler) parseSignedNumber() (int, bool) {
	neg := d.eat('n')
	start := len(d.s)
	n := 0
	any := false
	for len(d.s) > 0 && d.s[0] >= '0' && d.s[0] <= '9' {
		n = n*10 + int(d.s[0]-'0')
		d.s = d.s[1:]
		any = true
	}
	if !any {
		return 0, false
	}
	_ = start
	if neg {
		n = -n
	}
	return n, true
}

// parseName handles <name> ::= <nested-name> | <local-name> |
// <unscoped-template-name> <template-args> | <unscoped-name>.
func (d *demangler) parseName() (string, bool) {
	switch {
	case d.peek() == 'N':
		return d.parseNestedName()
	case d.peek() == 'Z':
		return d.parseLocalName()
	}

	// <unscoped-name> ::= <unqualified-name> | St <unqualified-name>
	stdPrefix := d.eatStr("St")
	startSubs := len(d.subs)

	var name string
	var ok bool
	if d.peek() == 'S' {
		// <unscoped-template-name> via <substitution>.
		name, ok = d.parseSubstitution()
	} else {
		name, ok = d.parseUnqualifiedName("")
	}
	if !ok {
		return "", false
	}
	if stdPrefix {
		name = "std::" + name
	}
	if len(d.subs) == startSubs {
		d.addSub(name)
	}

	if d.peek() == 'I' {
		args, ok := d.parseTemplateArgs()
		if !ok {
			return "", false
		}
		name = name + "<" + strings.Join(args, ", ") + ">"
		d.addSub(name)
	}
	return name, true
}

// parseLocalName handles <local-name> ::= Z <encoding> E <name> [_<seq>]
// | Z <encoding> E s [_<seq>] - an entity (static local, lambda, ...)
// scoped inside a function body.
func (d *demangler) parseLocalName() (string, bool) {
	if !d.eat('Z') {
		return "", false
	}
	fn, ok := d.parseTopLevel()
	if !ok {
		return "", false
	}
	if !d.eat('E') {
		return "", false
	}
	var local string
	if d.eat('s') {
		local = "string literal"
	} else {
		local, ok = d.parseName()
		if !ok {
			return "", false
		}
	}
	if d.eat('_') {
		for len(d.s) > 0 && d.s[0] >= '0' && d.s[0] <= '9' {
			d.s = d.s[1:]
		}
	}
	return fn + "::" + local, true
}

// parseNestedName handles
// <nested-name> ::= N [<CV-qualifiers>] [<ref-qualifier>] <prefix> <unqualified-name> E
//
//	| N [<CV-qualifiers>] [<ref-qualifier>] <template-prefix> <template-args> E
//
// via the standard unified "prefix" loop: each component (a plain
// name, or a template-id formed from the path built so far plus
// <template-args>) extends the running path and is added to the
// substitution table in turn.
func (d *demangler) parseNestedName() (string, bool) {
	if !d.eat('N') {
		return "", false
	}
	for d.peek() == 'r' || d.peek() == 'V' || d.peek() == 'K' {
		d.s = d.s[1:]
	}
	if d.eat('R') || d.eat('O') {
		// ref-qualifier - doesn't affect the name.
	}

	var path, lastComponent string
	for {
		switch {
		case d.eat('E'):
			if path == "" {
				return "", false
			}
			return path, true
		case d.peek() == 'S':
			sub, ok := d.parseSubstitution()
			if !ok {
				return "", false
			}
			path = sub
			lastComponent = sub
		case d.peek() == 'I':
			if path == "" {
				return "", false
			}
			args, ok := d.parseTemplateArgs()
			if !ok {
				return "", false
			}
			path = path + "<" + strings.Join(args, ", ") + ">"
			d.addSub(path)
			// lastComponent deliberately NOT updated to the templated
			// form: a constructor/destructor for a class template
			// (C1/D1/... right after this template-id) reuses just
			// the bare class name ("basic_string", not
			// "basic_string<char, ...>") per real compiler output -
			// see parseUnqualifiedName's ctor/dtor case, which is the
			// only reader of lastComponent.
		default:
			name, ok := d.parseUnqualifiedName(lastComponent)
			if !ok {
				return "", false
			}
			if path == "" {
				path = name
			} else {
				path = path + "::" + name
			}
			d.addSub(path)
			lastComponent = name
		}
	}
}

// parseUnqualifiedName handles <unqualified-name> plus any trailing
// <abi-tags> (silently dropped - decoration, not identity).
// priorComponent is the immediately preceding path component's own
// simple name, used to resolve a ctor/dtor-name back into that class's
// real name.
func (d *demangler) parseUnqualifiedName(priorComponent string) (string, bool) {
	var name string
	var ok bool
	switch {
	case d.peek() == 'C':
		if len(d.s) < 2 || (d.s[1] != '1' && d.s[1] != '2' && d.s[1] != '3') {
			return "", false
		}
		d.take(2)
		if priorComponent == "" {
			return "", false
		}
		name, ok = priorComponent, true
	case d.peek() == 'D' && len(d.s) > 1 && (d.s[1] == '0' || d.s[1] == '1' || d.s[1] == '2'):
		d.take(2)
		if priorComponent == "" {
			return "", false
		}
		name, ok = "~"+priorComponent, true
	case isOperatorCode(d.s):
		name, ok = d.parseOperatorName()
	case d.peek() >= '0' && d.peek() <= '9':
		name, ok = d.parseSourceName()
	case d.peek() == 'L' && len(d.s) > 1 && d.s[1] >= '0' && d.s[1] <= '9':
		// GNU extension: an internal-linkage ("static") entity's
		// source-name is prefixed with a bare 'L' marker (e.g.
		// "_ZL12g_debug_maps", or "9libunwindL24findUnwindSections...
		// " nested inside a namespace) - not part of the readable
		// name itself, just consumed and dropped.
		d.s = d.s[1:]
		name, ok = d.parseSourceName()
	case d.eatStr("Ut"):
		for len(d.s) > 0 && d.s[0] >= '0' && d.s[0] <= '9' {
			d.s = d.s[1:]
		}
		if !d.eat('_') {
			return "", false
		}
		name, ok = "unnamed-type", true
	case d.eatStr("Ul"):
		// <closure-type-name> Ul <lambda-sig> E [<number>] _
		depth := 1
		for depth > 0 {
			if len(d.s) == 0 {
				return "", false
			}
			if d.s[0] == 'E' {
				depth--
			}
			d.s = d.s[1:]
		}
		for len(d.s) > 0 && d.s[0] >= '0' && d.s[0] <= '9' {
			d.s = d.s[1:]
		}
		if !d.eat('_') {
			return "", false
		}
		name, ok = "lambda", true
	default:
		return "", false
	}
	if !ok {
		return "", false
	}
	for d.eat('B') {
		if _, ok := d.parseSourceName(); !ok {
			return "", false
		}
	}
	return name, true
}

func (d *demangler) parseSourceName() (string, bool) {
	n := 0
	any := false
	for len(d.s) > 0 && d.s[0] >= '0' && d.s[0] <= '9' {
		n = n*10 + int(d.s[0]-'0')
		d.s = d.s[1:]
		any = true
	}
	if !any || n <= 0 || n > len(d.s) {
		return "", false
	}
	return d.take(n), true
}

// operatorNames maps the two-letter Itanium operator-name code to its
// source-level spelling, matching c++filt's own phrasing.
var operatorNames = map[string]string{
	"nw": "new", "na": "new[]", "dl": "delete", "da": "delete[]",
	"ps": "+", "ng": "-", "ad": "&", "de": "*", "co": "~",
	"pl": "+", "mi": "-", "ml": "*", "dv": "/", "rm": "%",
	"an": "&", "or": "|", "eo": "^", "aS": "=",
	"pL": "+=", "mI": "-=", "mL": "*=", "dV": "/=", "rM": "%=",
	"aN": "&=", "oR": "|=", "eO": "^=",
	"ls": "<<", "rs": ">>", "lS": "<<=", "rS": ">>=",
	"eq": "==", "ne": "!=", "lt": "<", "gt": ">", "le": "<=", "ge": ">=", "ss": "<=>",
	"nt": "!", "aa": "&&", "oo": "||", "pp": "++", "mm": "--",
	"cm": ",", "pm": "->*", "pt": "->", "cl": "()", "ix": "[]", "qu": "?",
}

func isOperatorCode(s string) bool {
	if len(s) < 2 {
		return false
	}
	if s[:2] == "cv" || s[:2] == "li" {
		return true
	}
	_, ok := operatorNames[s[:2]]
	return ok
}

func (d *demangler) parseOperatorName() (string, bool) {
	code := d.take(2)
	switch code {
	case "cv":
		t, ok := d.parseType()
		if !ok {
			return "", false
		}
		return "operator " + t, true
	case "li":
		n, ok := d.parseSourceName()
		if !ok {
			return "", false
		}
		return `operator""` + n, true
	}
	sym, ok := operatorNames[code]
	if !ok {
		return "", false
	}
	if code == "nw" || code == "na" || code == "dl" || code == "da" {
		return "operator " + sym, true
	}
	return "operator" + sym, true
}

// parseSubstitution handles <substitution> ::= S_ | S <seq-id> _ | St
// | Sa | Sb | Ss | Si | So | Sd.
func (d *demangler) parseSubstitution() (string, bool) {
	if !d.eat('S') {
		return "", false
	}
	switch {
	case d.eat('_'):
		return d.subAt(0)
	case d.eat('a'):
		return "std::allocator", true
	case d.eat('b'):
		return "std::basic_string", true
	case d.eat('s'):
		return "std::string", true
	case d.eat('i'):
		return "std::istream", true
	case d.eat('o'):
		return "std::ostream", true
	case d.eat('d'):
		return "std::iostream", true
	case d.eat('t'):
		return "std", true
	}
	seq := 0
	any := false
	for isSeqIDChar(d.peek()) {
		c := d.s[0]
		var v int
		switch {
		case c >= '0' && c <= '9':
			v = int(c - '0')
		default:
			v = int(c-'A') + 10
		}
		seq = seq*36 + v
		d.s = d.s[1:]
		any = true
	}
	if !any || !d.eat('_') {
		return "", false
	}
	return d.subAt(seq + 1)
}

func isSeqIDChar(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z')
}

func (d *demangler) subAt(idx int) (string, bool) {
	if idx < 0 || idx >= len(d.subs) {
		return "", false
	}
	return d.subs[idx], true
}

// parseTemplateArgs handles <template-args> ::= I <template-arg>+ E.
func (d *demangler) parseTemplateArgs() (args []string, ok bool) {
	if !d.eat('I') {
		return nil, false
	}
	for {
		if d.eat('E') {
			d.templateArgStack = append(d.templateArgStack, args)
			return args, true
		}
		a, ok := d.parseTemplateArg()
		if !ok {
			return nil, false
		}
		args = append(args, a)
	}
}

func (d *demangler) parseTemplateArg() (string, bool) {
	switch {
	case d.peek() == 'L':
		return d.parseExprPrimary()
	case d.eat('J'):
		var parts []string
		for !d.eat('E') {
			a, ok := d.parseTemplateArg()
			if !ok {
				return "", false
			}
			parts = append(parts, a)
		}
		return strings.Join(parts, ", "), true
	case d.eatStr("X"):
		return "", false // <expression> template arg - not supported
	}
	return d.parseType()
}

// parseExprPrimary handles L <type> <value> E, the encoding used for
// non-type template arguments that are literal constants.
func (d *demangler) parseExprPrimary() (string, bool) {
	if !d.eat('L') {
		return "", false
	}
	if d.eatStr("b0E") {
		return "false", true
	}
	if d.eatStr("b1E") {
		return "true", true
	}
	t, ok := d.parseType()
	if !ok {
		return "", false
	}
	n, ok := d.parseSignedNumber()
	if !ok || !d.eat('E') {
		return "", false
	}
	_ = t
	if n < 0 {
		return itoa(n), true
	}
	return itoa(n), true
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

// builtinTypes maps single-character Itanium builtin-type codes to
// their spelling.
var builtinTypes = map[byte]string{
	'v': "void", 'w': "wchar_t", 'b': "bool",
	'c': "char", 'a': "signed char", 'h': "unsigned char",
	's': "short", 't': "unsigned short",
	'i': "int", 'j': "unsigned int",
	'l': "long", 'm': "unsigned long",
	'x': "long long", 'y': "unsigned long long",
	'n': "__int128", 'o': "unsigned __int128",
	'f': "float", 'd': "double", 'e': "long double", 'g': "__float128",
	'z': "...",
}

// parseType handles <type>, covering the subset that actually appears
// as template arguments / class-enum-types in real-world mangled
// names: builtins, pointers/references/cv-qualifiers, arrays,
// function types, pointer-to-member, class/enum types (via <name>),
// substitutions, and template-parameter back-references.
func (d *demangler) parseType() (string, bool) {
	startSubs := len(d.subs)
	switch {
	case d.peek() == 'S' && !(len(d.s) > 1 && d.s[1] == 't'):
		// A bare "St..." here is std::-qualified <name>, not a
		// <substitution> - handled by the class-enum-type case below.
		return d.parseSubstitution()
	case d.peek() == 'S' && len(d.s) > 1 && d.s[1] == 't':
		return d.parseClassEnumType()
	}

	if b, ok := builtinTypes[d.peek()]; ok {
		d.s = d.s[1:]
		return b, true
	}

	switch d.peek() {
	case 'r', 'V', 'K':
		var flags []byte
		for d.peek() == 'r' || d.peek() == 'V' || d.peek() == 'K' {
			flags = append(flags, d.s[0])
			d.s = d.s[1:]
		}
		base, ok := d.parseType()
		if !ok {
			return "", false
		}
		for _, f := range flags {
			switch f {
			case 'K':
				base += " const"
			case 'V':
				base += " volatile"
			case 'r':
				base += " restrict"
			}
		}
		d.addSub(base)
		return base, true
	case 'P':
		d.s = d.s[1:]
		base, ok := d.parseType()
		if !ok {
			return "", false
		}
		r := base + "*"
		d.addSub(r)
		return r, true
	case 'R':
		d.s = d.s[1:]
		base, ok := d.parseType()
		if !ok {
			return "", false
		}
		r := base + "&"
		d.addSub(r)
		return r, true
	case 'O':
		d.s = d.s[1:]
		base, ok := d.parseType()
		if !ok {
			return "", false
		}
		r := base + "&&"
		d.addSub(r)
		return r, true
	case 'C':
		d.s = d.s[1:]
		base, ok := d.parseType()
		if !ok {
			return "", false
		}
		r := "_Complex " + base
		d.addSub(r)
		return r, true
	case 'G':
		d.s = d.s[1:]
		base, ok := d.parseType()
		if !ok {
			return "", false
		}
		r := "_Imaginary " + base
		d.addSub(r)
		return r, true
	case 'A':
		return d.parseArrayType()
	case 'M':
		return d.parseMemberPointerType()
	case 'F':
		return d.parseFunctionType()
	case 'T':
		return d.parseTemplateParam()
	case 'D':
		return d.parseVendorType()
	case 'u':
		d.s = d.s[1:]
		n, ok := d.parseSourceName()
		if !ok {
			return "", false
		}
		return n, true
	case 'N', 'Z':
		return d.parseClassEnumType()
	default:
		if d.peek() >= '0' && d.peek() <= '9' {
			return d.parseClassEnumType()
		}
	}
	_ = startSubs
	return "", false
}

// parseClassEnumType handles <class-enum-type> - a plain <name>
// (possibly with "std::" / template-id decoration), which is itself
// substitutable as a whole once fully formed. parseName already adds
// its own intermediate substitution entries; this only needs to make
// sure the FINAL result is registered too when parseName didn't
// already do so via its own template-args branch.
func (d *demangler) parseClassEnumType() (string, bool) {
	before := len(d.subs)
	name, ok := d.parseName()
	if !ok {
		return "", false
	}
	if len(d.subs) == before {
		d.addSub(name)
	}
	return name, true
}

func (d *demangler) parseArrayType() (string, bool) {
	if !d.eat('A') {
		return "", false
	}
	dim := ""
	if d.peek() >= '0' && d.peek() <= '9' {
		for d.peek() >= '0' && d.peek() <= '9' {
			dim += string(d.s[0])
			d.s = d.s[1:]
		}
	}
	if !d.eat('_') {
		return "", false
	}
	elem, ok := d.parseType()
	if !ok {
		return "", false
	}
	r := elem + "[" + dim + "]"
	d.addSub(r)
	return r, true
}

func (d *demangler) parseMemberPointerType() (string, bool) {
	if !d.eat('M') {
		return "", false
	}
	class, ok := d.parseType()
	if !ok {
		return "", false
	}
	member, ok := d.parseType()
	if !ok {
		return "", false
	}
	r := member + " " + class + "::*"
	d.addSub(r)
	return r, true
}

func (d *demangler) parseFunctionType() (string, bool) {
	if !d.eat('F') {
		return "", false
	}
	d.eat('Y') // extern "C" marker
	var params []string
	for d.peek() != 'E' && d.peek() != 'R' && d.peek() != 'O' && d.peek() != 0 {
		t, ok := d.parseType()
		if !ok {
			return "", false
		}
		params = append(params, t)
	}
	d.eat('R')
	d.eat('O')
	if !d.eat('E') {
		return "", false
	}
	if len(params) == 0 {
		return "", false
	}
	ret := params[0]
	rest := params[1:]
	if len(rest) == 1 && rest[0] == "void" {
		rest = nil
	}
	r := ret + " (" + strings.Join(rest, ", ") + ")"
	d.addSub(r)
	return r, true
}

func (d *demangler) parseTemplateParam() (string, bool) {
	if !d.eat('T') {
		return "", false
	}
	idx := 0
	if !d.eat('_') {
		for d.peek() >= '0' && d.peek() <= '9' {
			idx = idx*10 + int(d.s[0]-'0')
			d.s = d.s[1:]
		}
		idx++
		if !d.eat('_') {
			return "", false
		}
	}
	if len(d.templateArgStack) == 0 {
		return "", false
	}
	cur := d.templateArgStack[len(d.templateArgStack)-1]
	if idx < 0 || idx >= len(cur) {
		return "", false
	}
	return cur[idx], true
}

// parseVendorType handles the common "D<letter>" vendor-extended type
// codes actually seen in real Clang/libc++ output.
func (d *demangler) parseVendorType() (string, bool) {
	if !d.eat('D') {
		return "", false
	}
	switch {
	case d.eat('n'):
		return "std::nullptr_t", true
	case d.eat('a'):
		return "auto", true
	case d.eat('c'):
		return "decltype(auto)", true
	case d.eat('i'):
		return "char32_t", true
	case d.eat('s'):
		return "char16_t", true
	case d.eat('u'):
		return "char8_t", true
	case d.eat('h'):
		return "half", true
	case d.eat('f'):
		return "decimal32", true
	case d.eat('e'):
		return "decimal64", true
	case d.eat('g'):
		return "decimal128", true
	}
	return "", false
}
