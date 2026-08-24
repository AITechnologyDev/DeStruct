package java

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/destruct/destruct/internal/ir"
)

// TestDollarToDot mirrors internal/jvm's own test for the identical
// logic (duplicated here rather than shared - see dollarToDot's own
// doc comment for why): an ordinary nested class reads with dots, but
// a synthetic anonymous/local class - digit right after the '$' - must
// keep it, since "Outer.3" isn't valid Java syntax.
func TestDollarToDot(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"ordinary nested class", "Outer$Inner", "Outer.Inner"},
		{"anonymous class", "Outer$3", "Outer$3"},
		{"local class", "Outer$1LocalClass", "Outer$1LocalClass"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := dollarToDot(c.in); got != c.want {
				t.Errorf("dollarToDot(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

// TestGenerateClass_NativeMethodHasNoBody exercises the actual
// template end to end: a real bug had a native (and, the same bug, an
// abstract) method rendered with a "{ // TODO }" body - illegal Java,
// since a native/abstract method declaration must end in a bare ";"
// with no body at all.
func TestGenerateClass_NativeMethodHasNoBody(t *testing.T) {
	class := &ir.Class{
		Name:   "Sample",
		Access: ir.AccPublic,
		Methods: []*ir.Method{
			{
				Name:       "doNative",
				Access:     ir.AccPublic | ir.AccNative,
				ReturnType: &ir.PrimitiveType{Name: "void"},
				// Body intentionally nil: a native method has no Code
				// attribute in the real class file, which is exactly
				// what triggers the old "// TODO" body fallback.
			},
			{
				Name:       "doAbstract",
				Access:     ir.AccPublic | ir.AccAbstract,
				ReturnType: &ir.PrimitiveType{Name: "void"},
			},
		},
	}

	dir := t.TempDir()
	g := NewGenerator(Options{OutputDir: dir})
	if err := g.GenerateClass(class); err != nil {
		t.Fatalf("GenerateClass: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(dir, "Sample.java"))
	if err != nil {
		t.Fatalf("reading generated file: %v", err)
	}
	src := string(data)

	if !strings.Contains(src, "native void doNative();") {
		t.Errorf("expected \"native void doNative();\" (no body) in output, got:\n%s", src)
	}
	if strings.Contains(src, "doNative() {") {
		t.Errorf("native method must not have a \"{\" body, got:\n%s", src)
	}
	if !strings.Contains(src, "abstract void doAbstract();") {
		t.Errorf("expected \"abstract void doAbstract();\" (no body) in output, got:\n%s", src)
	}
	if strings.Contains(src, "doAbstract() {") {
		t.Errorf("abstract method must not have a \"{\" body, got:\n%s", src)
	}
	if strings.Contains(src, "// TODO") {
		t.Errorf("native/abstract methods should never fall back to the \"// TODO\" body placeholder, got:\n%s", src)
	}
}

// TestGenerateClass_OrdinaryMethodStillGetsBody guards against an
// overcorrection: only native/abstract methods should lose their body -
// an ordinary method with no decompiled body yet (Body == nil for some
// OTHER reason - a genuine decompilation gap, not because it's
// native/abstract) must still fall back to "{ // TODO }", since it DOES
// have a real implementation in the class file that was just not
// recovered, unlike a native/abstract method which never had one.
func TestGenerateClass_OrdinaryMethodStillGetsBody(t *testing.T) {
	class := &ir.Class{
		Name:   "Sample",
		Access: ir.AccPublic,
		Methods: []*ir.Method{
			{
				Name:       "notYetDecompiled",
				Access:     ir.AccPublic,
				ReturnType: &ir.PrimitiveType{Name: "void"},
			},
		},
	}

	dir := t.TempDir()
	g := NewGenerator(Options{OutputDir: dir})
	if err := g.GenerateClass(class); err != nil {
		t.Fatalf("GenerateClass: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(dir, "Sample.java"))
	if err != nil {
		t.Fatalf("reading generated file: %v", err)
	}
	src := string(data)

	if !strings.Contains(src, "notYetDecompiled() {") {
		t.Errorf("expected an ordinary method to still get a \"{\" body, got:\n%s", src)
	}
	if !strings.Contains(src, "// TODO") {
		t.Errorf("expected the \"// TODO\" placeholder for a genuinely undecompiled ordinary method, got:\n%s", src)
	}
}
