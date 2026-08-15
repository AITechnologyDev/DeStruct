package jvm

import "github.com/destruct/destruct/internal/ir"

// findSignatureAttr looks up the optional "Signature" attribute (JVMS
// 4.7.9) among attrs and decodes it: the attribute's data is a single u2
// constant pool index pointing at a UTF8 entry holding the actual
// signature string. Returns ("", false) if no such attribute is present
// or its data is malformed.
func findSignatureAttr(cf *ClassFile, attrs []AttributeInfo) (string, bool) {
	for _, attr := range attrs {
		if cf.GetUTF8(attr.NameIndex) != "Signature" {
			continue
		}
		if len(attr.Data) < 2 {
			return "", false
		}
		idx := uint16(attr.Data[0])<<8 | uint16(attr.Data[1])
		return cf.GetUTF8(idx), true
	}
	return "", false
}

// =============================================================================
// Generic type signature parsing.
//
// Every field/method in a class file has an ordinary "descriptor" (e.g.
// "Ljava/util/List;") which is ALWAYS erased - it never carries generic
// type arguments, by design (that's what type erasure means). If the
// class was compiled with generics actually visible at that point, the
// compiler ALSO emits a separate, optional "Signature" attribute holding
// the real generic type in a distinct textual grammar (JVMS 4.7.9.1),
// e.g. "Ljava/util/List<Ljava/lang/String;>;" for List<String>.
//
// This file implements that grammar for FIELD signatures only for now:
//
//   FieldSignature: ReferenceTypeSignature
//   ReferenceTypeSignature: ClassTypeSignature | '[' ReferenceTypeSignature (array) | TypeVar
//   ClassTypeSignature: 'L' Identifier ('/' Identifier)* TypeArguments? ('.' Identifier TypeArguments?)* ';'
//   TypeArguments: '<' TypeArgument+ '>'
//   TypeArgument: '*' | ('+' | '-')? ReferenceTypeSignature
//   TypeVariableSignature: 'T' Identifier ';'
//
// Method parameter/return-type generics and class-level type parameters
// (class Box<T>) use a larger grammar built on top of this one and are
// not yet implemented - see parseFieldSignature's doc comment.
// =============================================================================

// sigParser is a minimal cursor over a generic signature string.
type sigParser struct {
	s   string
	pos int
}

func (p *sigParser) peek() byte {
	if p.pos >= len(p.s) {
		return 0
	}
	return p.s[p.pos]
}

func (p *sigParser) advance() byte {
	c := p.peek()
	p.pos++
	return c
}

// parseFieldSignature parses a field's Signature attribute string (the
// FieldSignature grammar above) into an ir.Type carrying real generic
// type arguments, or (nil, false) if sig is empty, malformed, or uses a
// construct this parser doesn't yet handle (e.g. a bare type variable
// reference at the top level, which can't be meaningfully rendered
// without the enclosing class's type parameter declarations - not yet
// parsed; see this file's header comment).
//
// On any parse failure, the caller should fall back to the field's
// ordinary (erased) descriptor type rather than propagate an error -
// generic signature information is inherently a "nice to have" layered
// on top of the always-present, always-correct erased type, so failing
// to recover it should never be worse than not having attempted to.
func parseFieldSignature(sig string) (ir.Type, bool) {
	if sig == "" {
		return nil, false
	}
	p := &sigParser{s: sig}
	t, ok := p.parseReferenceTypeSignature()
	if !ok {
		return nil, false
	}
	return t, true
}

func (p *sigParser) parseReferenceTypeSignature() (ir.Type, bool) {
	switch p.peek() {
	case 'L':
		return p.parseClassTypeSignature()
	case '[':
		p.advance()
		elem, ok := p.parseTypeSignature()
		if !ok {
			return nil, false
		}
		return &ir.ArrayType{Elem: elem}, true
	case 'T':
		p.advance()
		start := p.pos
		for p.peek() != 0 && p.peek() != ';' {
			p.advance()
		}
		name := p.s[start:p.pos]
		if p.peek() != ';' {
			return nil, false
		}
		p.advance()
		// A type variable reference (e.g. a field of type T inside a
		// generic class) renders as just its name at a use site - "T",
		// not "T extends Foo" (bounds only appear once, at the
		// declaration itself: class Box<T extends Foo>). Represented as
		// TypeVarRef, not ClassType, so it's never mistaken for a real
		// (importable) class reference.
		return &ir.TypeVarRef{Name: name}, true
	default:
		return nil, false
	}
}

// parseTypeSignature parses any signature type, including primitives
// (needed inside array element types - "[I" for int[]).
func (p *sigParser) parseTypeSignature() (ir.Type, bool) {
	switch p.peek() {
	case 'B':
		p.advance()
		return &ir.PrimitiveType{Name: "byte"}, true
	case 'C':
		p.advance()
		return &ir.PrimitiveType{Name: "char"}, true
	case 'D':
		p.advance()
		return &ir.PrimitiveType{Name: "double"}, true
	case 'F':
		p.advance()
		return &ir.PrimitiveType{Name: "float"}, true
	case 'I':
		p.advance()
		return &ir.PrimitiveType{Name: "int"}, true
	case 'J':
		p.advance()
		return &ir.PrimitiveType{Name: "long"}, true
	case 'S':
		p.advance()
		return &ir.PrimitiveType{Name: "short"}, true
	case 'Z':
		p.advance()
		return &ir.PrimitiveType{Name: "boolean"}, true
	default:
		return p.parseReferenceTypeSignature()
	}
}

func (p *sigParser) parseClassTypeSignature() (ir.Type, bool) {
	if p.advance() != 'L' {
		return nil, false
	}
	start := p.pos
	for p.peek() != 0 && p.peek() != '<' && p.peek() != ';' && p.peek() != '.' {
		p.advance()
	}
	name := p.s[start:p.pos]

	var typeArgs []ir.Type
	if p.peek() == '<' {
		var ok bool
		typeArgs, ok = p.parseTypeArguments()
		if !ok {
			return nil, false
		}
	}

	// Nested/inner class suffix (Outer<T>.Inner<U> style) - JVMS calls
	// these ClassTypeSignatureSuffix. Real code rarely puts generics on
	// an inner class reference this way; when it does, fold the suffix
	// into a dotted name (Outer.Inner) and keep only the LAST segment's
	// type arguments, which is what the Java source's own <...> at that
	// position would correspond to.
	for p.peek() == '.' {
		p.advance()
		segStart := p.pos
		for p.peek() != 0 && p.peek() != '<' && p.peek() != ';' && p.peek() != '.' {
			p.advance()
		}
		name = name + "." + p.s[segStart:p.pos]
		typeArgs = nil
		if p.peek() == '<' {
			var ok bool
			typeArgs, ok = p.parseTypeArguments()
			if !ok {
				return nil, false
			}
		}
	}

	if p.peek() != ';' {
		return nil, false
	}
	p.advance()

	javaName := classNameToJavaName(name)
	return &ir.ClassType{Name: javaName, TypeArgs: typeArgs}, true
}

func (p *sigParser) parseTypeArguments() ([]ir.Type, bool) {
	if p.advance() != '<' {
		return nil, false
	}
	var args []ir.Type
	for p.peek() != '>' {
		if p.peek() == 0 {
			return nil, false
		}
		arg, ok := p.parseTypeArgument()
		if !ok {
			return nil, false
		}
		args = append(args, arg)
	}
	p.advance() // consume '>'
	return args, true
}

// parseMethodSignature parses a method's Signature attribute string
// (MethodSignature grammar: TypeParameters? '(' JavaTypeSignature* ')'
// Result ThrowsSignature*) into real generic parameter and return types.
//
// Type parameter DECLARATIONS (the "<T extends Foo>" part, if present at
// the very start) are recognized just enough to skip past them
// correctly - they are not yet rendered at the method declaration site
// (that needs its own follow-up, alongside class-level "class Box<T>"
// support), but skipping them correctly is what lets the parser reach
// the actual parameter/return types that follow, which is this
// function's real goal. A type variable USED within a parameter or
// return type (e.g. "(TT;)TT;" for a method taking and returning T)
// still resolves via parseReferenceTypeSignature's 'T' case above,
// rendering as its bare name.
//
// Throws-clause entries (^ExceptionType) are parsed just enough to skip
// past them for the same reason, and are not yet returned/rendered -
// matching the pre-existing gap where Method.Exceptions isn't populated
// anywhere in this package yet.
//
// On any parse failure, returns (nil, nil, false); the caller should
// fall back to the method's ordinary (erased) descriptor-derived types
// entirely (not mix-and-match resolved/unresolved parameters), so a
// malformed or unusual signature never produces a partially-wrong
// parameter list.
func parseMethodSignature(sig string) (params []ir.Type, ret ir.Type, ok bool) {
	if sig == "" {
		return nil, nil, false
	}
	p := &sigParser{s: sig}

	if p.peek() == '<' {
		if !p.skipTypeParameters() {
			return nil, nil, false
		}
	}

	if p.advance() != '(' {
		return nil, nil, false
	}
	for p.peek() != ')' {
		if p.peek() == 0 {
			return nil, nil, false
		}
		pt, ptOk := p.parseTypeSignature()
		if !ptOk {
			return nil, nil, false
		}
		params = append(params, pt)
	}
	p.advance() // consume ')'

	if p.peek() == 'V' {
		p.advance()
		ret = nil // void
	} else {
		var retOk bool
		ret, retOk = p.parseTypeSignature()
		if !retOk {
			return nil, nil, false
		}
	}

	// Throws-clause: '^' (ClassTypeSignature | TypeVariableSignature)
	// repeated. Skip each one; not yet surfaced to the caller (see doc
	// comment above).
	for p.peek() == '^' {
		p.advance()
		if p.peek() == 'T' {
			if _, tvOk := p.parseReferenceTypeSignature(); !tvOk {
				return nil, nil, false
			}
		} else {
			if _, ctOk := p.parseClassTypeSignature(); !ctOk {
				return nil, nil, false
			}
		}
	}

	return params, ret, true
}

// parseClassSignature parses a class's Signature attribute string
// (ClassSignature grammar: TypeParameters? SuperclassSignature
// InterfaceSignature*) and returns its type parameter declarations.
// The superclass/interface signatures themselves are not returned here -
// GetSuperClassName/GetInterfaceNames (the erased versions) already
// cover that; only the class's OWN type parameters are new information
// this parser adds, since those have no erased-descriptor equivalent at
// all (there's nothing to erase them FROM - a class's type parameter
// list only ever exists in the Signature attribute).
//
// On any parse failure, or when the class has no TypeParameters section
// at all (a non-generic class, or a generic class whose Signature
// attribute for some other reason couldn't be read), returns (nil,
// false); the caller should simply not render a type parameter list, a
// safe and correct choice either way (a non-generic class has none to
// show, and a generic one whose signature failed to parse still
// decompiles correctly - just without that particular piece of
// information).
func parseClassSignature(sig string) ([]*ir.TypeParam, bool) {
	if sig == "" || sig[0] != '<' {
		return nil, false
	}
	p := &sigParser{s: sig}
	return p.parseTypeParametersDecl()
}

// parseTypeParametersDecl parses a TypeParameters section ('<'
// TypeParameter+ '>') and returns each one's name and bounds, unlike
// skipTypeParameters (used by parseMethodSignature, which only needs to
// skip past this section to reach what follows it, not keep its
// content).
func (p *sigParser) parseTypeParametersDecl() ([]*ir.TypeParam, bool) {
	if p.advance() != '<' {
		return nil, false
	}
	var params []*ir.TypeParam
	for p.peek() != '>' {
		if p.peek() == 0 {
			return nil, false
		}
		nameStart := p.pos
		for p.peek() != 0 && p.peek() != ':' {
			p.advance()
		}
		name := p.s[nameStart:p.pos]

		var bounds []ir.Type
		for p.peek() == ':' {
			p.advance()
			if p.peek() == 'L' || p.peek() == '[' || p.peek() == 'T' {
				bound, ok := p.parseReferenceTypeSignature()
				if !ok {
					return nil, false
				}
				// Drop the implicit "extends Object" bound every type
				// parameter's class bound has when no real bound was
				// written in the source - real Java source never
				// spells that out ("<T>", not "<T extends Object>").
				if ct, isClass := bound.(*ir.ClassType); !isClass || ct.Name != "Object" || len(ct.TypeArgs) != 0 {
					bounds = append(bounds, bound)
				}
			}
		}
		params = append(params, &ir.TypeParam{Name: name, Bounds: bounds})
	}
	p.advance() // consume '>'
	return params, true
}
// skipTypeParameters consumes a TypeParameters section ('<' TypeParameter+
// '>') without building any representation of it - see
// parseMethodSignature's doc comment for why. TypeParameter is
// "Identifier ClassBound TraitBound*", ClassBound/TraitBound are each
// ':' ReferenceTypeSignature? (the ReferenceTypeSignature is absent for
// ClassBound when the type parameter's class bound is implicitly
// Object, e.g. "T:Ljava/lang/Object;" is what "T" alone becomes, but
// "N::Ljava/lang/Comparable;" - IMPLICIT Object bound plus an interface
// bound - has nothing between the two colons).
func (p *sigParser) skipTypeParameters() bool {
	if p.advance() != '<' {
		return false
	}
	for p.peek() != '>' {
		if p.peek() == 0 {
			return false
		}
		// Identifier
		for p.peek() != 0 && p.peek() != ':' {
			p.advance()
		}
		// ClassBound and any TraitBounds: each starts with ':',
		// optionally followed by a ReferenceTypeSignature.
		for p.peek() == ':' {
			p.advance()
			if p.peek() == 'L' || p.peek() == '[' || p.peek() == 'T' {
				if _, ok := p.parseReferenceTypeSignature(); !ok {
					return false
				}
			}
		}
	}
	p.advance() // consume '>'
	return true
}

func (p *sigParser) parseTypeArgument() (ir.Type, bool) {
	switch p.peek() {
	case '*':
		p.advance()
		return &ir.WildcardType{}, true
	case '+':
		p.advance()
		bound, ok := p.parseReferenceTypeSignature()
		if !ok {
			return nil, false
		}
		return &ir.WildcardType{Bound: bound, Extends: true}, true
	case '-':
		p.advance()
		bound, ok := p.parseReferenceTypeSignature()
		if !ok {
			return nil, false
		}
		return &ir.WildcardType{Bound: bound, Extends: false}, true
	default:
		return p.parseReferenceTypeSignature()
	}
}
