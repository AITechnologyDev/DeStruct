package arm64lift

import (
	"fmt"
	"io"
	"strings"

	"github.com/destruct/destruct/internal/ir"
)

// RenderStmts writes stmts as C-like pseudocode to w, indented one
// level ("    ") per depth. Recurses into IfStmt/WhileStmt/DoWhileStmt
// bodies so nested control flow prints in full; every other statement
// type (AssignStmt, ExprStmt, ReturnStmt, BreakStmt, ContinueStmt, ...)
// renders via its own ir.Stmt String() method instead, since none of
// them have anything nested worth recursing into.
//
// The single shared renderer for every consumer of this package's own
// output - cmd/lifttest (one function at a time) and the pipeline's
// whole-binary decompile (internal/pipeline) - so both stay in sync
// automatically with any future ir.Stmt addition instead of drifting
// into two, subtly different printers.
func RenderStmts(w io.Writer, stmts []ir.Stmt, depth int) {
	indent := strings.Repeat("    ", depth)
	for _, s := range stmts {
		switch v := s.(type) {
		case *ir.IfStmt:
			fmt.Fprintf(w, "%sif (%s) {\n", indent, v.Cond)
			if v.Then != nil {
				RenderStmts(w, v.Then.Statements, depth+1)
			}
			fmt.Fprintf(w, "%s}", indent)
			if v.Else != nil && len(v.Else.Statements) > 0 {
				fmt.Fprint(w, " else {\n")
				RenderStmts(w, v.Else.Statements, depth+1)
				fmt.Fprintf(w, "%s}", indent)
			}
			fmt.Fprintln(w)
		case *ir.WhileStmt:
			fmt.Fprintf(w, "%swhile (%s) {\n", indent, v.Cond)
			if v.Body != nil {
				RenderStmts(w, v.Body.Statements, depth+1)
			}
			fmt.Fprintf(w, "%s}\n", indent)
		case *ir.DoWhileStmt:
			fmt.Fprintf(w, "%sdo {\n", indent)
			if v.Body != nil {
				RenderStmts(w, v.Body.Statements, depth+1)
			}
			fmt.Fprintf(w, "%s} while (%s);\n", indent, v.Cond)
		default:
			fmt.Fprintf(w, "%s%s\n", indent, s)
		}
	}
}
