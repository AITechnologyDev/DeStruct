package arm64lift

import (
	"fmt"
	"strings"

	"github.com/destruct/destruct/internal/ir"
)

// FormatFunction renders a lifted function's body as C-like source text -
// e.g. for cmd/lifttest's output, or any future caller that wants to see
// what LiftFunction actually produced. name is used only in the leading
// comment; params are rendered as the declared signature.
func FormatFunction(name string, params []string, stmts []ir.Stmt) string {
	var b strings.Builder
	fmt.Fprintf(&b, "// %s(%s)\n", name, strings.Join(params, ", "))
	for _, s := range stmts {
		b.WriteString(RenderStmt(s, 1))
		b.WriteByte('\n')
	}
	return b.String()
}

// RenderStmt renders one statement as C-like source text at the given
// indentation depth (one level = 4 spaces), recursing into nested if/
// while/for/block bodies. This is deliberately separate from ir.Stmt's
// own String() method (internal/ir/string.go), which renders a nested
// body as a flat "{ ... }" placeholder - a fine one-line summary, but
// useless for actually reading a lifted function's control flow. Any
// statement shape this package's lifter doesn't produce (SwitchStmt,
// TryStmt, ForEachStmt, ...) falls back to that same placeholder String().
func RenderStmt(s ir.Stmt, depth int) string {
	indent := strings.Repeat("    ", depth)
	switch v := s.(type) {
	case *ir.IfStmt:
		var b strings.Builder
		fmt.Fprintf(&b, "%sif (%s) {\n", indent, v.Cond)
		b.WriteString(renderBlock(v.Then, depth+1))
		fmt.Fprintf(&b, "%s}", indent)
		if v.Else != nil && len(v.Else.Statements) > 0 {
			b.WriteString(" else {\n")
			b.WriteString(renderBlock(v.Else, depth+1))
			fmt.Fprintf(&b, "%s}", indent)
		}
		return b.String()
	case *ir.WhileStmt:
		var b strings.Builder
		fmt.Fprintf(&b, "%swhile (%s) {\n", indent, v.Cond)
		b.WriteString(renderBlock(v.Body, depth+1))
		fmt.Fprintf(&b, "%s}", indent)
		return b.String()
	case *ir.ForStmt:
		var b strings.Builder
		fmt.Fprintf(&b, "%sfor (%s; %s; %s) {\n", indent, stmtInline(v.Init), exprString(v.Cond), stmtInline(v.Post))
		b.WriteString(renderBlock(v.Body, depth+1))
		fmt.Fprintf(&b, "%s}", indent)
		return b.String()
	case *ir.BlockStmt:
		var b strings.Builder
		fmt.Fprintf(&b, "%s{\n", indent)
		b.WriteString(renderBlock(v.Block, depth+1))
		fmt.Fprintf(&b, "%s}", indent)
		return b.String()
	default:
		return indent + fmt.Sprint(s)
	}
}

func renderBlock(b *ir.Block, depth int) string {
	if b == nil {
		return ""
	}
	var out strings.Builder
	for _, s := range b.Statements {
		out.WriteString(RenderStmt(s, depth))
		out.WriteByte('\n')
	}
	return out.String()
}

// stmtInline renders a single statement without a trailing semicolon, for
// a for-loop's init/post clauses (e.g. "i = 0", not "i = 0;").
func stmtInline(s ir.Stmt) string {
	if s == nil {
		return ""
	}
	return strings.TrimSuffix(fmt.Sprint(s), ";")
}

func exprString(e ir.Expr) string {
	if e == nil {
		return ""
	}
	return fmt.Sprint(e)
}
