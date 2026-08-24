package ir

// CloneStmts returns a deep copy of a []Stmt slice: every Stmt, and every
// Expr/Type/Block/Stmt reachable from it, is duplicated into fresh node
// instances. nil-safe (both the slice and any nil Stmt/Expr/Type values
// inside it).
//
// This exists for callers - such as a memoizing decompiler cache - that
// need to hand out the "same" statements to more than one place in a tree
// being built. Every consumer of this package's IR (the code generators,
// import collectors, statement renderers) walks Stmt/Expr trees assuming
// they are trees: each node has exactly one parent. If the same *IfStmt or
// *ExprStmt pointer is appended into two different parent blocks, the tree
// silently becomes a DAG, and any subsequent recursive walk re-visits (and,
// for something like a renderer producing source text, re-emits) that
// shared subtree once per parent - which can turn what should be linear
// work back into exponential work. Cloning on hand-out keeps every
// consumer's simplifying "it's a tree" assumption true.
func CloneStmts(stmts []Stmt) []Stmt {
	if stmts == nil {
		return nil
	}
	out := make([]Stmt, len(stmts))
	for i, s := range stmts {
		out[i] = CloneStmt(s)
	}
	return out
}

// CloneBlock deep-copies a *Block (nil-safe).
func CloneBlock(b *Block) *Block {
	if b == nil {
		return nil
	}
	return &Block{Statements: CloneStmts(b.Statements)}
}

// CloneStmt deep-copies a single Stmt (nil-safe; unknown/nil-interface
// values pass through unchanged since there is nothing to copy).
func CloneStmt(s Stmt) Stmt {
	switch v := s.(type) {
	case nil:
		return nil
	case *AssignStmt:
		return &AssignStmt{Target: CloneExpr(v.Target), Value: CloneExpr(v.Value)}
	case *ReturnStmt:
		return &ReturnStmt{Value: CloneExpr(v.Value)}
	case *ExprStmt:
		return &ExprStmt{Expr: CloneExpr(v.Expr)}
	case *IfStmt:
		return &IfStmt{Cond: CloneExpr(v.Cond), Then: CloneBlock(v.Then), Else: CloneBlock(v.Else)}
	case *WhileStmt:
		return &WhileStmt{Cond: CloneExpr(v.Cond), Body: CloneBlock(v.Body)}
	case *DoWhileStmt:
		return &DoWhileStmt{Cond: CloneExpr(v.Cond), Body: CloneBlock(v.Body)}
	case *ForStmt:
		return &ForStmt{Init: CloneStmt(v.Init), Cond: CloneExpr(v.Cond), Post: CloneStmt(v.Post), Body: CloneBlock(v.Body)}
	case *SwitchStmt:
		cases := make([]*CaseClause, len(v.Cases))
		for i, c := range v.Cases {
			cases[i] = cloneCaseClause(c)
		}
		return &SwitchStmt{Target: CloneExpr(v.Target), Cases: cases, Default: CloneBlock(v.Default)}
	case *TryStmt:
		catches := make([]*CatchClause, len(v.Catches))
		for i, c := range v.Catches {
			catches[i] = cloneCatchClause(c)
		}
		var resources []*ResourceDecl
		if v.Resources != nil {
			resources = make([]*ResourceDecl, len(v.Resources))
			for i, r := range v.Resources {
				resources[i] = &ResourceDecl{VarType: CloneType(r.VarType), VarName: r.VarName, Init: CloneExpr(r.Init)}
			}
		}
		return &TryStmt{Resources: resources, Body: CloneBlock(v.Body), Catches: catches, Finally: CloneBlock(v.Finally)}
	case *ForEachStmt:
		return &ForEachStmt{VarName: v.VarName, VarType: CloneType(v.VarType), Expr: CloneExpr(v.Expr), Body: CloneBlock(v.Body)}
	case *BlockStmt:
		return &BlockStmt{Block: CloneBlock(v.Block)}
	case *ThrowStmt:
		return &ThrowStmt{Value: CloneExpr(v.Value)}
	case *VarDeclStmt:
		return &VarDeclStmt{Name: v.Name, Type: CloneType(v.Type), Init: CloneExpr(v.Init)}
	case *BreakStmt:
		return &BreakStmt{}
	case *ContinueStmt:
		return &ContinueStmt{}
	default:
		// Unknown Stmt implementation (e.g. added outside this package):
		// return as-is rather than panicking. This only risks reintroducing
		// aliasing for node kinds that don't exist in this package today.
		return s
	}
}

func cloneCaseClause(c *CaseClause) *CaseClause {
	if c == nil {
		return nil
	}
	values := make([]Expr, len(c.Values))
	for i, e := range c.Values {
		values[i] = CloneExpr(e)
	}
	return &CaseClause{Values: values, Body: CloneBlock(c.Body), Fallthrough: c.Fallthrough}
}

func cloneCatchClause(c *CatchClause) *CatchClause {
	if c == nil {
		return nil
	}
	return &CatchClause{VarName: c.VarName, VarType: CloneType(c.VarType), Body: CloneBlock(c.Body)}
}

// CloneExpr deep-copies a single Expr (nil-safe).
func CloneExpr(e Expr) Expr {
	switch v := e.(type) {
	case nil:
		return nil
	case *IntLit:
		cp := *v
		return &cp
	case *LongLit:
		cp := *v
		return &cp
	case *FloatLit:
		cp := *v
		return &cp
	case *DoubleLit:
		cp := *v
		return &cp
	case *StringLit:
		cp := *v
		return &cp
	case *BoolLit:
		cp := *v
		return &cp
	case *NullLit:
		return &NullLit{}
	case *LocalVar:
		cp := *v
		return &cp
	case *FieldAccess:
		return &FieldAccess{Object: CloneExpr(v.Object), Name: v.Name}
	case *MethodCall:
		return &MethodCall{Object: CloneExpr(v.Object), Name: v.Name, Args: cloneExprs(v.Args)}
	case *StaticMethodCall:
		return &StaticMethodCall{Class: v.Class, Method: v.Method, Args: cloneExprs(v.Args)}
	case *NewExpr:
		return &NewExpr{Type: v.Type, Args: cloneExprs(v.Args)}
	case *NewArrayExpr:
		return &NewArrayExpr{ElemType: CloneType(v.ElemType), Size: CloneExpr(v.Size)}
	case *ArrayInitExpr:
		return &ArrayInitExpr{ElemType: CloneType(v.ElemType), Elems: cloneExprs(v.Elems)}
	case *ArrayAccess:
		return &ArrayAccess{Array: CloneExpr(v.Array), Index: CloneExpr(v.Index)}
	case *CastExpr:
		return &CastExpr{Type: CloneType(v.Type), Expr: CloneExpr(v.Expr)}
	case *ThisExpr:
		return &ThisExpr{}
	case *SuperExpr:
		return &SuperExpr{}
	case *BinaryExpr:
		return &BinaryExpr{Op: v.Op, Left: CloneExpr(v.Left), Right: CloneExpr(v.Right)}
	case *UnaryExpr:
		return &UnaryExpr{Op: v.Op, Expr: CloneExpr(v.Expr)}
	case *TernaryExpr:
		return &TernaryExpr{Cond: CloneExpr(v.Cond), TrueExpr: CloneExpr(v.TrueExpr), FalseExpr: CloneExpr(v.FalseExpr)}
	case *MethodRefExpr:
		cp := *v
		return &cp
	case *LambdaExpr:
		params := make([]string, len(v.Params))
		copy(params, v.Params)
		return &LambdaExpr{Params: params, Body: CloneBlock(v.Body)}
	case *ClassLiteral:
		cp := *v
		return &cp
	case *ClassType:
		// ClassType implements both typeNode and exprNode.
		return cloneClassType(v)
	default:
		return e
	}
}

func cloneExprs(exprs []Expr) []Expr {
	if exprs == nil {
		return nil
	}
	out := make([]Expr, len(exprs))
	for i, e := range exprs {
		out[i] = CloneExpr(e)
	}
	return out
}

// CloneType deep-copies a single Type (nil-safe).
func CloneType(t Type) Type {
	switch v := t.(type) {
	case nil:
		return nil
	case *PrimitiveType:
		cp := *v
		return &cp
	case *ArrayType:
		return &ArrayType{Elem: CloneType(v.Elem)}
	case *ClassType:
		return cloneClassType(v)
	case *WildcardType:
		return &WildcardType{Bound: CloneType(v.Bound), Extends: v.Extends}
	case *TypeVarRef:
		cp := *v
		return &cp
	default:
		return t
	}
}

// cloneClassType deep-copies a ClassType, including its generic type
// arguments (each of which may itself be a ClassType, WildcardType,
// ArrayType, etc. - CloneType handles all of those recursively).
func cloneClassType(v *ClassType) *ClassType {
	var args []Type
	if v.TypeArgs != nil {
		args = make([]Type, len(v.TypeArgs))
		for i, a := range v.TypeArgs {
			args[i] = CloneType(a)
		}
	}
	return &ClassType{Name: v.Name, TypeArgs: args}
}
