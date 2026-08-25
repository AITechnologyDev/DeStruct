package jvm

import (
	"testing"

	"github.com/destruct/destruct/internal/ir"
)

// TestDecompileClassFile_SuperAndThisCallArgs decompiles a REAL,
// javac-compiled .class file (testdata/CtorArgsWidget.class, built
// from testdata/CtorArgsWidget.java - see that file for the original
// source and how to regenerate the fixture) exercising the actual bug:
// invokespecial <init> on "this" was previously being dropped
// entirely, silently discarding its arguments (see decompileInvoke's
// own doc comment in decoder.go), so EVERY constructor that called a
// parameterized super() or this() rendered a bare, argument-less
// "super();" instead - both syntactically wrong (doesn't match the
// superclass's real constructor signature) and a real loss of
// information about what's actually passed through.
func TestDecompileClassFile_SuperAndThisCallArgs(t *testing.T) {
	prog, err := DecompileClassFile("testdata/CtorArgsWidget.class")
	if err != nil {
		t.Fatalf("DecompileClassFile: %v", err)
	}
	if len(prog.Classes) != 1 {
		t.Fatalf("expected exactly 1 class, got %d", len(prog.Classes))
	}
	class := prog.Classes[0]

	var withOneParam, noArgCtor *ir.Method
	for _, m := range class.Methods {
		if m.Name != "<init>" {
			continue
		}
		if len(m.Params) == 1 {
			withOneParam = m
		} else {
			noArgCtor = m
		}
	}

	if withOneParam == nil {
		t.Fatalf("expected a 1-param constructor among %v", class.Methods)
	}
	if withOneParam.Body == nil || len(withOneParam.Body.Statements) == 0 {
		t.Fatalf("expected the 1-param constructor to have a non-empty body")
	}
	superCall, ok := withOneParam.Body.Statements[0].(*ir.SuperCallStmt)
	if !ok {
		t.Fatalf("expected the 1-param constructor's first statement to be a SuperCallStmt, got %T: %v", withOneParam.Body.Statements[0], withOneParam.Body.Statements[0])
	}
	if len(superCall.Args) != 2 {
		t.Fatalf("expected super(name, 1) to carry 2 args (both forwarded from the source's own \"super(name, 1);\"), got %d: %v", len(superCall.Args), superCall.Args)
	}
	if lit, ok := superCall.Args[1].(*ir.IntLit); !ok || lit.Value != 1 {
		t.Errorf("expected the second super() arg to be the int literal 1, got %#v", superCall.Args[1])
	}

	if noArgCtor == nil {
		t.Fatalf("expected a no-arg constructor among %v", class.Methods)
	}
	if noArgCtor.Body == nil || len(noArgCtor.Body.Statements) == 0 {
		t.Fatalf("expected the no-arg constructor to have a non-empty body")
	}
	thisCall, ok := noArgCtor.Body.Statements[0].(*ir.ThisCallStmt)
	if !ok {
		t.Fatalf("expected the no-arg constructor's first statement to be a ThisCallStmt (it delegates via \"this(\\\"default\\\");\"), got %T: %v", noArgCtor.Body.Statements[0], noArgCtor.Body.Statements[0])
	}
	if len(thisCall.Args) != 1 {
		t.Fatalf("expected this(\"default\") to carry 1 arg, got %d: %v", len(thisCall.Args), thisCall.Args)
	}
	if lit, ok := thisCall.Args[0].(*ir.StringLit); !ok || lit.Value != "default" {
		t.Errorf("expected the this() arg to be the string literal \"default\", got %#v", thisCall.Args[0])
	}
}

// TestDecompileClassFile_AstoreLocalGetsDeclared decompiles a REAL,
// javac-compiled .class file (testdata/AstoreRetype.class, built
// WITHOUT -g so it has no LocalVariableTable at all - see that file's
// own doc comment) exercising the actual bug: collectLocalTypes had no
// case at all for Astore/Astore_<n> (only the primitive stores), so a
// reference-typed local with no debug info never got an entry in its
// types map and was silently omitted from the method's declarations
// entirely, even though it's used later in the body - "buf" in the
// real test/lunacy/classes_merge.jar's NPStringFog.decode rendered as
// an undeclared identifier for exactly this reason.
func TestDecompileClassFile_AstoreLocalGetsDeclared(t *testing.T) {
	prog, err := DecompileClassFile("testdata/AstoreRetype.class")
	if err != nil {
		t.Fatalf("DecompileClassFile: %v", err)
	}
	if len(prog.Classes) != 1 {
		t.Fatalf("expected exactly 1 class, got %d", len(prog.Classes))
	}
	class := prog.Classes[0]

	var build *ir.Method
	for _, m := range class.Methods {
		if m.Name == "build" {
			build = m
		}
	}
	if build == nil {
		t.Fatalf("expected a \"build\" method among %v", class.Methods)
	}
	if build.Body == nil {
		t.Fatalf("expected \"build\" to have a body")
	}

	var decl *ir.VarDeclStmt
	for _, s := range build.Body.Statements {
		if v, ok := s.(*ir.VarDeclStmt); ok {
			decl = v
		}
	}
	if decl == nil {
		t.Fatalf("expected a VarDeclStmt for the undeclared local (\"buf\" in the original source) among %v, got none at all - this is the bug", build.Body.Statements)
	}
	class_, ok := decl.Type.(*ir.ClassType)
	if !ok {
		t.Fatalf("expected the inferred type to be a ClassType (from the \"new ByteArrayOutputStream(...)\" + invokespecial <init> pattern), got %T: %v", decl.Type, decl.Type)
	}
	if class_.Name != "java.io.ByteArrayOutputStream" {
		t.Errorf("expected the inferred type to be java.io.ByteArrayOutputStream (the invokespecial <init> target's own class, NOT its void descriptor return type), got %q", class_.Name)
	}
}
