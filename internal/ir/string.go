package ir

import (
	"fmt"
	"strings"
)

func (s *AssignStmt) String() string {
	return fmt.Sprintf("%s = %s;", s.Target, s.Value)
}

func (s *ReturnStmt) String() string {
	if s.Value == nil {
		return "return;"
	}
	return fmt.Sprintf("return %s;", s.Value)
}

func (s *ExprStmt) String() string {
	return fmt.Sprintf("%s;", s.Expr)
}

func (s *IfStmt) String() string {
	if s.Else != nil && len(s.Else.Statements) > 0 {
		return fmt.Sprintf("if (%s) { ... } else { ... }", s.Cond)
	}
	return fmt.Sprintf("if (%s) { ... }", s.Cond)
}

func (s *WhileStmt) String() string {
	return fmt.Sprintf("while (%s) { ... }", s.Cond)
}

func (s *DoWhileStmt) String() string {
	return fmt.Sprintf("do { ... } while (%s);", s.Cond)
}

func (s *ForStmt) String() string {
	return fmt.Sprintf("for (...; %s; ...) { ... }", s.Cond)
}

func (s *TryStmt) String() string {
	return "try { ... } catch { ... }"
}

func (s *ForEachStmt) String() string {
	return fmt.Sprintf("for (%s %s : %s) { ... }", s.VarType, s.VarName, s.Expr)
}

func (s *SwitchStmt) String() string {
	result := fmt.Sprintf("switch (%s) {\n", s.Target)
	for _, c := range s.Cases {
		for _, v := range c.Values {
			result += fmt.Sprintf("case %s:\n", v)
		}
		result += "    ...\n"
	}
	if s.Default != nil {
		result += "default:\n    ...\n"
	}
	result += "}"
	return result
}

func (s *BlockStmt) String() string {
	return "{ ... }"
}

func (s *ThrowStmt) String() string {
	return fmt.Sprintf("throw %s;", s.Value)
}

func (s *VarDeclStmt) String() string {
	if s.Init != nil {
		return fmt.Sprintf("%s %s = %s;", s.Type, s.Name, s.Init)
	}
	return fmt.Sprintf("%s %s;", s.Type, s.Name)
}

func (s *BreakStmt) String() string {
	return "break;"
}

func (s *ContinueStmt) String() string {
	return "continue;"
}

func (e *IntLit) String() string {
	return fmt.Sprintf("%d", e.Value)
}

func (e *LongLit) String() string {
	return fmt.Sprintf("%dL", e.Value)
}

func (e *FloatLit) String() string {
	return fmt.Sprintf("%ff", e.Value)
}

func (e *DoubleLit) String() string {
	return fmt.Sprintf("%fd", e.Value)
}

func (e *StringLit) String() string {
	return fmt.Sprintf("\"%s\"", e.Value)
}

func (e *BoolLit) String() string {
	if e.Value {
		return "true"
	}
	return "false"
}

func (e *NullLit) String() string {
	return "null"
}

func (e *LocalVar) String() string {
	return e.Name
}

func (e *FieldAccess) String() string {
	if e.Object != nil {
		return fmt.Sprintf("%s.%s", e.Object, e.Name)
	}
	return e.Name
}

func (e *MethodCall) String() string {
	args := make([]string, len(e.Args))
	for i, a := range e.Args {
		args[i] = fmt.Sprint(a)
	}
	s := strings.Join(args, ", ")
	if e.Object != nil {
		return fmt.Sprintf("%s.%s(%s)", e.Object, e.Name, s)
	}
	return fmt.Sprintf("%s(%s)", e.Name, s)
}

func (e *StaticMethodCall) String() string {
	args := make([]string, len(e.Args))
	for i, a := range e.Args {
		args[i] = fmt.Sprint(a)
	}
	return fmt.Sprintf("%s.%s(%s)", e.Class, e.Method, strings.Join(args, ", "))
}

func (e *IndirectCall) String() string {
	args := make([]string, len(e.Args))
	for i, a := range e.Args {
		args[i] = fmt.Sprint(a)
	}
	return fmt.Sprintf("(%s)(%s)", e.Callee, strings.Join(args, ", "))
}

func (e *NewExpr) String() string {
	args := make([]string, len(e.Args))
	for i, a := range e.Args {
		args[i] = fmt.Sprint(a)
	}
	s := strings.Join(args, ", ")
	if e.Type != "" {
		return fmt.Sprintf("new %s(%s)", e.Type, s)
	}
	return fmt.Sprintf("new Object(%s)", s)
}

func (e *NewArrayExpr) String() string {
	return fmt.Sprintf("new %s[]", e.ElemType)
}

func (e *ArrayInitExpr) String() string {
	elems := make([]string, len(e.Elems))
	for i, elem := range e.Elems {
		elems[i] = fmt.Sprint(elem)
	}
	return fmt.Sprintf("new %s[]{ %s }", e.ElemType, strings.Join(elems, ", "))
}

func (e *ArrayAccess) String() string {
	return fmt.Sprintf("%s[%s]", e.Array, e.Index)
}

func (e *CastExpr) String() string {
	return fmt.Sprintf("(%s)%s", e.Type, e.Expr)
}

func (e *ThisExpr) String() string {
	return "this"
}

func (e *SuperExpr) String() string {
	return "super"
}

func (e *MethodRefExpr) String() string {
	return e.ClassName + "::" + e.MethodName
}

func (e *LambdaExpr) String() string {
	params := "(" + strings.Join(e.Params, ", ") + ")"
	if e.Body == nil || len(e.Body.Statements) == 0 {
		return params + " -> {}"
	}
	if len(e.Body.Statements) == 1 {
		if ret, ok := e.Body.Statements[0].(*ReturnStmt); ok && ret.Value != nil {
			return params + " -> " + fmt.Sprint(ret.Value)
		}
		if es, ok := e.Body.Statements[0].(*ExprStmt); ok {
			return params + " -> " + fmt.Sprint(es.Expr)
		}
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s -> {\n", params)
	for _, s := range e.Body.Statements {
		fmt.Fprintf(&b, "\t\t\t%s\n", s)
	}
	b.WriteString("\t\t}")
	return b.String()
}

func (e *ClassLiteral) String() string {
	return e.Type
}

func (e *BinaryExpr) String() string {
	if e.Left == nil {
		return e.Op
	}
	if e.Right == nil {
		return fmt.Sprintf("%s%s", e.Op, e.Left)
	}
	left := fmt.Sprint(e.Left)
	right := fmt.Sprint(e.Right)

	if be, ok := e.Left.(*BinaryExpr); ok {
		if needsParens(be.Op, e.Op, true) == 1 {
			left = "(" + left + ")"
		}
	}
	if be, ok := e.Right.(*BinaryExpr); ok {
		if needsParens(be.Op, e.Op, false) == 1 {
			right = "(" + right + ")"
		}
	}
	return fmt.Sprintf("%s %s %s", left, e.Op, right)
}

func opPrecedence(op string) int {
	switch op {
	case "||":
		return 1
	case "&&":
		return 2
	case "|":
		return 3
	case "^":
		return 4
	case "&":
		return 5
	case "==", "!=":
		return 6
	case "<", ">", "<=", ">=":
		return 7
	case ">>", "<<", ">>>":
		return 8
	case "+", "-":
		return 9
	case "*", "/", "%":
		return 10
	}
	return 0
}

func needsParens(childOp, parentOp string, isLeft bool) int {
	cp := opPrecedence(childOp)
	pp := opPrecedence(parentOp)
	if cp < pp {
		return 1
	}
	if cp == pp && !isLeft {
		return 1
	}
	return 0
}

func (e *UnaryExpr) String() string {
	return fmt.Sprintf("%s%s", e.Op, e.Expr)
}

func (e *TernaryExpr) String() string {
	return fmt.Sprintf("%s ? %s : %s", e.Cond, e.TrueExpr, e.FalseExpr)
}

func (t *PrimitiveType) String() string {
	switch t.Name {
	case "byte", "sbyte":
		return "byte"
	case "char":
		return "char"
	case "double":
		return "double"
	case "float":
		return "float"
	case "int":
		return "int"
	case "long":
		return "long"
	case "short":
		return "short"
	case "bool", "boolean":
		return "boolean"
	case "void":
		return "void"
	default:
		return t.Name
	}
}

func (t *ArrayType) String() string {
	return fmt.Sprintf("%s[]", t.Elem)
}

func (t *ClassType) String() string {
	return t.Name
}
