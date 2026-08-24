package jvm

import "testing"

// TestDollarToDot exercises the '$' -> '.' conversion used everywhere
// an internal (bytecode) class name gets rendered as Java source: an
// ordinary named nested class should read with dots, but a synthetic
// anonymous/local class - named with a digit right after the '$' -
// must keep its '$', since "Outer.3" isn't valid Java (a digit right
// after a literal '.' lexes as the start of a number, not a member
// name), while "Outer$3" is at least a syntactically valid identifier.
func TestDollarToDot(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"ordinary nested class", "Outer$Inner", "Outer.Inner"},
		{"two levels of nesting", "Outer$Middle$Inner", "Outer.Middle.Inner"},
		{"anonymous class", "Outer$3", "Outer$3"},
		{"local class (digit then more identifier chars)", "Outer$1LocalClass", "Outer$1LocalClass"},
		{"anonymous class nested inside a named one", "Outer$Inner$2", "Outer.Inner$2"},
		{"no dollar at all", "PlainClass", "PlainClass"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := dollarToDot(c.in); got != c.want {
				t.Errorf("dollarToDot(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

// TestSanitizeMethodName exercises real-world synthetic bytecode
// method names this decompiler has to render as literal Java source
// identifiers - names the JVM constant pool allows but Java source
// syntax doesn't, taken directly from test/classes_merge.jar (a real,
// R8-hardened Android APK used as this package's own manual test
// fixture).
func TestSanitizeMethodName(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"init passes through unchanged", "<init>", "<init>"},
		{"clinit passes through unchanged", "<clinit>", "<clinit>"},
		{"ordinary name is untouched", "onCreate", "onCreate"},
		{"leading hyphen (nestmate field accessor)", "-$$Nest$fgetwebView", "_$$Nest$fgetwebView"},
		{"embedded hyphens (lambda body, dotted class name)", "lambda$onCreate$0$video-likee-lite-MainActivity", "lambda$onCreate$0$video_likee_lite_MainActivity"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := sanitizeMethodName(c.in); got != c.want {
				t.Errorf("sanitizeMethodName(%q) = %q, want %q", c.in, got, c.want)
			}
			// Whatever sanitizeMethodName produces (besides the two
			// sentinel values) must actually be usable as a Java
			// identifier: every rune is a letter, '_', '$', or a digit
			// not in first position.
			if c.in == "<init>" || c.in == "<clinit>" {
				return
			}
			got := sanitizeMethodName(c.in)
			for i, r := range got {
				isLetter := (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')
				isDigit := r >= '0' && r <= '9'
				switch {
				case isLetter || r == '_' || r == '$':
				case isDigit && i > 0:
				default:
					t.Errorf("sanitizeMethodName(%q) = %q contains an invalid Java identifier character %q at position %d", c.in, got, r, i)
				}
			}
		})
	}
}

// TestEscapeIdent covers the reserved-keyword escaping used for both
// parameter and local variable names - a Class<?> parameter naturally
// lowercases to "class" (see classParamNames' own doc comment for the
// happier alternative that avoids this for that specific case), and
// obfuscated/debug-info-preserved bytecode could in principle carry
// any other reserved word too.
func TestEscapeIdent(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"class", "class_"},
		{"int", "int_"},
		{"new", "new_"},
		{"this", "this_"},
		{"clazz", "clazz"},
		{"str", "str"},
		{"", ""},
	}
	for _, c := range cases {
		if got := escapeIdent(c.in); got != c.want {
			t.Errorf("escapeIdent(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestDisambiguate covers the per-method name-collision numbering used
// when two parameters or locals independently want the same name -
// most commonly two "int" parameters both naturally inferred as "i"
// once a class has been stripped of real debug info (real -O0/R8
// output, not a contrived case).
func TestDisambiguate(t *testing.T) {
	used := map[string]bool{}
	got := []string{
		disambiguate("i", used),
		disambiguate("i", used),
		disambiguate("i", used),
		disambiguate("str", used),
	}
	want := []string{"i", "i2", "i3", "str"}
	for i, w := range want {
		if got[i] != w {
			t.Errorf("disambiguate call #%d = %q, want %q (full sequence: %v)", i, got[i], w, got)
		}
	}
}

// TestInferParamName_PrimitiveKeysMatchParsedType guards against the
// exact bug this test would have caught: typeParamNames must be keyed
// by ParsedType.Base's OWN spelling (see parseTypeAtIndex in
// descriptors.go - 'Z' parses to Base "bool", not "boolean"; 'B'
// parses to Base "sbyte", not "byte"), not Java's own primitive
// keywords - a mismatched key silently falls through to the generic
// derivation instead of ever being used, with no compiler or test
// failure to reveal it.
func TestInferParamName_PrimitiveKeysMatchParsedType(t *testing.T) {
	cases := []struct {
		base string
		want string
	}{
		{"bool", "flag"},
		{"sbyte", "b"},
		{"char", "c"},
		{"short", "s"},
		{"int", "i"},
		{"long", "l"},
		{"float", "f"},
		{"double", "d"},
	}
	for _, c := range cases {
		got := inferParamName(ParsedType{Base: c.base}, 0)
		if got != c.want {
			t.Errorf("inferParamName(Base:%q) = %q, want %q", c.base, got, c.want)
		}
	}
}

// TestInferParamName_ClassParamNames confirms classParamNames (keyed
// by full internal/slash-separated class name, matching ParsedType.Base
// for a reference type) is actually consulted - it was previously
// defined but never referenced anywhere, so every reference-typed
// parameter fell through to the generic lowercase-first-letter
// derivation regardless of what this map said.
func TestInferParamName_ClassParamNames(t *testing.T) {
	cases := []struct {
		base string
		want string
	}{
		{"java/lang/Thread", "thread"},
		{"java/lang/String", "str"},
		{"java/lang/Class", "clazz"},
		{"java/util/List", "list"},
	}
	for _, c := range cases {
		got := inferParamName(ParsedType{Base: c.base}, 0)
		if got != c.want {
			t.Errorf("inferParamName(Base:%q) = %q, want %q", c.base, got, c.want)
		}
	}
}

// TestInferParamName_UnknownClassLowercasesFirstLetter is the generic
// fallback path for a reference type not in classParamNames - and the
// specific case that produces the reserved word "class" for a
// java.lang.Class parameter if classParamNames' own "clazz" mapping
// (see above) is ever removed; escapeIdent (see buildParamNames) is
// what actually guards against that downstream, not this function
// itself, which just confirms the raw (still keyword-colliding)
// derivation is what a caller needs to escape.
func TestInferParamName_UnknownClassLowercasesFirstLetter(t *testing.T) {
	got := inferParamName(ParsedType{Base: "com/example/SomeWidget"}, 0)
	if got != "someWidget" {
		t.Errorf("inferParamName(Base:%q) = %q, want %q", "com/example/SomeWidget", got, "someWidget")
	}
}
