package ir

type Program struct {
	Classes []*Class
}

type Class struct {
	Name       string
	Package    string
	Access     AccessFlags
	SuperClass string
	Interfaces []string
	// TypeParams holds this class's own generic type parameter
	// declarations, if any - e.g. "class Box<T extends Comparable<T>>"
	// has one: {Name: "T", Bounds: [ClassType{Comparable<T>}]}. Empty/nil
	// for a non-generic class or when this information isn't available
	// (the Signature attribute is optional).
	TypeParams []*TypeParam
	Fields     []*Field
	Methods    []*Method
}

// TypeParam is one generic type parameter declaration (on a class or,
// potentially in the future, a method): a name and zero or more bounds.
// Multiple bounds ("<T extends Comparable<T> & Serializable>") are
// rendered joined with " & ", matching Java's own intersection-type
// bound syntax. No bounds at all (a plain "<T>") is the common case,
// corresponding to an implicit Object bound that Signature always spells
// out explicitly as "Ljava/lang/Object;" - that implicit Object bound is
// dropped rather than rendered, since real Java source never writes it.
type TypeParam struct {
	Name   string
	Bounds []Type
}

type Field struct {
	Name   string
	Type   Type
	Access AccessFlags
}

type Method struct {
	Name       string
	Access     AccessFlags
	Params     []*Param
	ReturnType Type
	Body       *Block
	Exceptions []string
}

type Param struct {
	Name string
	Type Type
}

type Block struct {
	Statements []Stmt
}

type Stmt interface {
	stmtNode()
}

type Expr interface {
	exprNode()
}

type Type interface {
	typeNode()
}

type AccessFlags uint16

const (
	AccPublic       AccessFlags = 0x0001
	AccPrivate      AccessFlags = 0x0002
	AccProtected    AccessFlags = 0x0004
	AccStatic       AccessFlags = 0x0008
	AccFinal        AccessFlags = 0x0010
	AccSynchronized AccessFlags = 0x0020
	AccVolatile     AccessFlags = 0x0040
	AccTransient    AccessFlags = 0x0080
	AccNative       AccessFlags = 0x0100
	AccAbstract     AccessFlags = 0x0400
	AccInterface    AccessFlags = 0x0200
	AccEnum         AccessFlags = 0x4000
)

func (f AccessFlags) Has(flag AccessFlags) bool {
	return f&flag != 0
}

func (f AccessFlags) IsPublic() bool       { return f.Has(AccPublic) }
func (f AccessFlags) IsPrivate() bool      { return f.Has(AccPrivate) }
func (f AccessFlags) IsProtected() bool    { return f.Has(AccProtected) }
func (f AccessFlags) IsStatic() bool       { return f.Has(AccStatic) }
func (f AccessFlags) IsFinal() bool        { return f.Has(AccFinal) }
func (f AccessFlags) IsSynchronized() bool { return f.Has(AccSynchronized) }
func (f AccessFlags) IsVolatile() bool     { return f.Has(AccVolatile) }
func (f AccessFlags) IsTransient() bool    { return f.Has(AccTransient) }
func (f AccessFlags) IsNative() bool       { return f.Has(AccNative) }
func (f AccessFlags) IsAbstract() bool     { return f.Has(AccAbstract) }
func (f AccessFlags) IsInterface() bool    { return f.Has(AccInterface) }
func (f AccessFlags) IsEnum() bool         { return f.Has(AccEnum) }

type (
	PrimitiveType struct{ Name string }
	ArrayType     struct{ Elem Type }
	// TypeArgs holds this type's generic type arguments, if any (e.g.
	// List<String> has one: ClassType{Name: "String"}). Empty/nil for a
	// non-generic type or when generic information isn't available (the
	// Signature attribute is optional and only present when the class
	// was compiled with generics actually used at this point).
	//
	// A wildcard argument (List<? extends Number>, List<?>) is
	// represented as a WildcardType (see below), not a bare ClassType,
	// so String() can tell "? extends Number" apart from a real type
	// named "Number".
	ClassType struct {
		Name     string
		TypeArgs []Type
	}
	// TypeVarRef is a reference to a generic type parameter at a use
	// site - e.g. the "T" in "private T value;" inside a generic class.
	// Kept structurally distinct from ClassType (which always names a
	// real, importable class) so the generator's import collector can
	// tell "this needs an import" apart from "this is just a type
	// variable name" exactly, rather than guessing from the name's
	// shape (a real class could coincidentally be named with a single
	// letter too).
	TypeVarRef struct {
		Name string
	}
	// WildcardType represents a generic wildcard type argument: "?"
	// (Bound == nil), "? extends X" (Extends == true), or "? super X"
	// (Extends == false).
	WildcardType struct {
		Bound   Type // nil for a bare "?"
		Extends bool
	}
)

func (*PrimitiveType) typeNode() {}
func (*ArrayType) typeNode()     {}
func (*ClassType) typeNode()     {}
func (*ClassType) exprNode()     {}
func (*WildcardType) typeNode()  {}
func (*TypeVarRef) typeNode()    {}

type (
	AssignStmt struct {
		Target Expr
		Value  Expr
	}
	ReturnStmt struct {
		Value Expr
	}
	ExprStmt struct {
		Expr Expr
	}
	IfStmt struct {
		Cond Expr
		Then *Block
		Else *Block
	}
	WhileStmt struct {
		Cond Expr
		Body *Block
	}
	// DoWhileStmt is a "do { body } while (cond);" loop: unlike
	// WhileStmt, the condition is checked AFTER the body runs, so the
	// body always executes at least once.
	DoWhileStmt struct {
		Cond Expr
		Body *Block
	}
	ForStmt struct {
		Init Stmt
		Cond Expr
		Post Stmt
		Body *Block
	}
	SwitchStmt struct {
		Target  Expr
		Cases   []*CaseClause
		Default *Block
	}
	CaseClause struct {
		Values []Expr
		Body   *Block
		// Fallthrough is true when this case's body, in the original
		// bytecode, does NOT end with a goto to the switch statement's
		// merge point - meaning control falls straight through into the
		// next case (or default) rather than exiting the switch. The
		// generator must omit the usual trailing "break;" in this case,
		// or the decompiled source would behave differently from what
		// the bytecode actually does.
		Fallthrough bool
	}
	TryStmt struct {
		// Resources holds each try-with-resources declaration, if any
		// ("try (FileInputStream fis = new FileInputStream(file))") -
		// nil/empty for an ordinary try. When present, these render as
		// the parenthesized resource list rather than as ordinary
		// statements inside Body.
		Resources []*ResourceDecl
		Body      *Block
		Catches   []*CatchClause
		Finally   *Block
	}
	// ResourceDecl is one resource declaration in a try-with-resources
	// statement's parentheses: "Type varName = initExpr".
	ResourceDecl struct {
		VarType Type
		VarName string
		Init    Expr
	}
	ForEachStmt struct {
		VarName string
		VarType Type
		Expr    Expr
		Body    *Block
	}
	CatchClause struct {
		VarName string
		VarType Type
		Body    *Block
	}
	BlockStmt struct {
		Block *Block
	}
	ThrowStmt struct {
		Value Expr
	}
	VarDeclStmt struct {
		Name string
		Type Type
		Init Expr
	}
	BreakStmt    struct{}
	ContinueStmt struct{}
)

func (*AssignStmt) stmtNode()   {}
func (*ReturnStmt) stmtNode()   {}
func (*ExprStmt) stmtNode()     {}
func (*IfStmt) stmtNode()       {}
func (*WhileStmt) stmtNode()    {}
func (*DoWhileStmt) stmtNode()  {}
func (*ForStmt) stmtNode()      {}
func (*SwitchStmt) stmtNode()   {}
func (*TryStmt) stmtNode()      {}
func (*ForEachStmt) stmtNode()  {}
func (*BlockStmt) stmtNode()    {}
func (*ThrowStmt) stmtNode()    {}
func (*VarDeclStmt) stmtNode()  {}
func (*BreakStmt) stmtNode()    {}
func (*ContinueStmt) stmtNode() {}

type (
	IntLit    struct{ Value int64 }
	LongLit   struct{ Value int64 }
	FloatLit  struct{ Value float32 }
	DoubleLit struct{ Value float64 }
	StringLit struct{ Value string }
	BoolLit   struct{ Value bool }
	NullLit   struct{}

	LocalVar    struct{ Name string }
	FieldAccess struct {
		Object Expr
		Name   string
	}
	MethodCall struct {
		Object Expr
		Name   string
		Args   []Expr
	}
	StaticMethodCall struct {
		Class  string
		Method string
		Args   []Expr
	}
	// IndirectCall is a call through an arbitrary callee EXPRESSION
	// rather than a statically known name - a function-pointer call, or
	// (the far more common real-world case) a C++ virtual-dispatch
	// thunk jumping through a loaded vtable slot, where there's no
	// symbol to resolve at all.
	IndirectCall struct {
		Callee Expr
		Args   []Expr
	}
	NewExpr struct {
		Type string
		Args []Expr
	}
	NewArrayExpr struct {
		ElemType Type
		Size     Expr
	}
	ArrayInitExpr struct {
		ElemType Type
		Elems    []Expr
	}
	ArrayAccess struct {
		Array Expr
		Index Expr
	}
	CastExpr struct {
		Type Type
		Expr Expr
	}
	ThisExpr   struct{}
	SuperExpr  struct{}
	BinaryExpr struct {
		Op    string
		Left  Expr
		Right Expr
	}
	UnaryExpr struct {
		Op   string
		Expr Expr
	}
	TernaryExpr struct {
		Cond      Expr
		TrueExpr  Expr
		FalseExpr Expr
	}
	MethodRefExpr struct {
		ClassName  string
		MethodName string
	}
	// LambdaExpr represents an inline lambda expression, e.g. "(x) -> x.foo()"
	// or "(x, y) -> { ...; return z; }". Params holds the lambda's
	// parameter names (types are normally omitted at the call site in
	// real Java lambda syntax, so they aren't tracked here). Body holds
	// the lambda's decompiled statements; the generator renders a
	// single-statement body ending in return as the short expression
	// form when possible, and a full block otherwise.
	LambdaExpr struct {
		Params []string
		Body   *Block
	}
	ClassLiteral struct {
		Type string
	}
)

func (*IntLit) exprNode()           {}
func (*LongLit) exprNode()          {}
func (*FloatLit) exprNode()         {}
func (*DoubleLit) exprNode()        {}
func (*StringLit) exprNode()        {}
func (*BoolLit) exprNode()          {}
func (*NullLit) exprNode()          {}
func (*LocalVar) exprNode()         {}
func (*FieldAccess) exprNode()      {}
func (*MethodCall) exprNode()       {}
func (*StaticMethodCall) exprNode() {}
func (*IndirectCall) exprNode()     {}
func (*NewExpr) exprNode()          {}
func (*NewArrayExpr) exprNode()     {}
func (*ArrayInitExpr) exprNode()    {}
func (*ArrayAccess) exprNode()      {}
func (*CastExpr) exprNode()         {}
func (*ThisExpr) exprNode()         {}
func (*SuperExpr) exprNode()        {}
func (*BinaryExpr) exprNode()       {}
func (*UnaryExpr) exprNode()        {}
func (*TernaryExpr) exprNode()      {}
func (*MethodRefExpr) exprNode()    {}
func (*LambdaExpr) exprNode()       {}
func (*ClassLiteral) exprNode()     {}
