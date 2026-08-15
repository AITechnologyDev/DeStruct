package java

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/template"

	"github.com/destruct/destruct/internal/ir"
)

type Options struct {
	OutputDir string
	Deobf     bool
	Verbose   bool
}

type Generator struct {
	opts Options
}

func NewGenerator(opts Options) *Generator {
	if opts.OutputDir == "" {
		opts.OutputDir = "output"
	}
	return &Generator{opts: opts}
}

func (g *Generator) Generate(prog *ir.Program) error {
	if err := os.MkdirAll(g.opts.OutputDir, 0o755); err != nil {
		return fmt.Errorf("creating output dir: %w", err)
	}

	for _, class := range prog.Classes {
		if err := g.generateClass(class); err != nil {
			return fmt.Errorf("generating class %s: %w", class.Name, err)
		}
	}

	return nil
}

// GenerateClass writes a single class's .java file. It does the same work
// Generate does per iteration, exposed directly so callers that decompile
// one class at a time (e.g. a streaming .jar pipeline that never holds more
// than one class's IR in memory at once) can write each .java file as soon
// as that class is ready, instead of accumulating a full *ir.Program first.
func (g *Generator) GenerateClass(class *ir.Class) error {
	if err := os.MkdirAll(g.opts.OutputDir, 0o755); err != nil {
		return fmt.Errorf("creating output dir: %w", err)
	}
	if err := g.generateClass(class); err != nil {
		return fmt.Errorf("generating class %s: %w", class.Name, err)
	}
	return nil
}

func (g *Generator) generateClass(class *ir.Class) error {
	pkgDir := strings.ReplaceAll(class.Package, ".", string(os.PathSeparator))
	dir := filepath.Join(g.opts.OutputDir, pkgDir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}

	filename := filepath.Join(dir, class.Name+".java")

	imports := collectImports(class)

	tmpl, err := template.New("class").Funcs(template.FuncMap{
		"acc": accessStr,
		"fmod": fieldModStr,
		"mmod": methodModStr,
		"typeName": func(t ir.Type) string {
			if t == nil {
				return "void"
			}
			return typeName(t)
		},
		"jtype": classNameToJava,
		"params": func(params []*ir.Param) string {
			var parts []string
			for _, p := range params {
				parts = append(parts, fmt.Sprintf("%s %s", typeName(p.Type), p.Name))
			}
			return strings.Join(parts, ", ")
		},
		"typeParams": func(params []*ir.TypeParam) string {
			if len(params) == 0 {
				return ""
			}
			var parts []string
			for _, tp := range params {
				s := tp.Name
				if len(tp.Bounds) > 0 {
					boundStrs := make([]string, len(tp.Bounds))
					for i, b := range tp.Bounds {
						boundStrs[i] = typeName(b)
					}
					s += " extends " + strings.Join(boundStrs, " & ")
				}
				parts = append(parts, s)
			}
			return "<" + strings.Join(parts, ", ") + ">"
		},
		"classKind": func(f ir.AccessFlags) string {
			if f.IsInterface() {
				return "interface"
			}
			if f.IsEnum() {
				return "enum"
			}
			return "class"
		},
		"isReturnVoid": func(s ir.Stmt) bool {
			if r, ok := s.(*ir.ReturnStmt); ok {
				return r.Value == nil
			}
			return false
		},
		"renderStmt": func(s ir.Stmt) string {
			return renderStmt(s, 2)
		},
		"hasSuper": func(s string) bool {
			return s != ""
		},
		"nonEmpty": func(s string) bool {
			return s != ""
		},
	}).Parse(javaTemplate)
	if err != nil {
		return err
	}

	type classData struct {
		*ir.Class
		Imports []string
	}
	data := &classData{
		Class:   class,
		Imports: imports,
	}

	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	return tmpl.Execute(f, data)
}

func accessStr(f ir.AccessFlags) string {
	if f.IsPublic() {
		return "public "
	}
	if f.IsPrivate() {
		return "private "
	}
	if f.IsProtected() {
		return "protected "
	}
	return ""
}

func fieldModStr(f ir.AccessFlags) string {
	var mods []string
	if f.IsStatic() {
		mods = append(mods, "static")
	}
	if f.IsFinal() {
		mods = append(mods, "final")
	}
	if f.IsVolatile() {
		mods = append(mods, "volatile")
	}
	if f.IsTransient() {
		mods = append(mods, "transient")
	}
	s := strings.Join(mods, " ")
	if s != "" {
		return s + " "
	}
	return ""
}

func methodModStr(f ir.AccessFlags) string {
	var mods []string
	if f.IsStatic() {
		mods = append(mods, "static")
	}
	if f.IsFinal() {
		mods = append(mods, "final")
	}
	if f.IsAbstract() {
		mods = append(mods, "abstract")
	}
	if f.IsNative() {
		mods = append(mods, "native")
	}
	if f.IsSynchronized() {
		mods = append(mods, "synchronized")
	}
	s := strings.Join(mods, " ")
	if s != "" {
		return s + " "
	}
	return ""
}

func negateCondExpr(e ir.Expr) ir.Expr {
	switch v := e.(type) {
	case *ir.UnaryExpr:
		if v.Op == "!" {
			return v.Expr
		}
		return &ir.UnaryExpr{Op: "!", Expr: e}
	case *ir.BinaryExpr:
		switch v.Op {
		case "==":
			return &ir.BinaryExpr{Op: "!=", Left: v.Left, Right: v.Right}
		case "!=":
			return &ir.BinaryExpr{Op: "==", Left: v.Left, Right: v.Right}
		case "<":
			return &ir.BinaryExpr{Op: ">=", Left: v.Left, Right: v.Right}
		case ">":
			return &ir.BinaryExpr{Op: "<=", Left: v.Left, Right: v.Right}
		case "<=":
			return &ir.BinaryExpr{Op: ">", Left: v.Left, Right: v.Right}
		case ">=":
			return &ir.BinaryExpr{Op: "<", Left: v.Left, Right: v.Right}
		}
	}
	return &ir.UnaryExpr{Op: "!", Expr: e}
}

func renderStmt(s ir.Stmt, depth int) string {
	indent := strings.Repeat("\t", depth)

	switch v := s.(type) {
	case *ir.VarDeclStmt:
		if v.Init != nil {
			return indent + fmt.Sprintf("%s %s = %s;", typeName(v.Type), v.Name, fmt.Sprint(v.Init))
		}
		return indent + fmt.Sprintf("%s %s;", typeName(v.Type), v.Name)
	case *ir.IfStmt:
		thenEmpty := len(v.Then.Statements) == 0
		elseHasContent := v.Else != nil && len(v.Else.Statements) > 0

		if thenEmpty && elseHasContent {
			negCond := negateCondExpr(v.Cond)
			result := indent + "if (" + fmt.Sprint(negCond) + ") {\n"
			for _, stmt := range v.Else.Statements {
				result += renderStmt(stmt, depth+1) + "\n"
			}
			result += indent + "}"
			return result
		}

		result := indent + "if (" + fmt.Sprint(v.Cond) + ") {\n"
		for _, stmt := range v.Then.Statements {
			result += renderStmt(stmt, depth+1) + "\n"
		}
		result += indent + "}"
		if v.Else != nil && len(v.Else.Statements) > 0 {
			result += " else {\n"
			for _, stmt := range v.Else.Statements {
				result += renderStmt(stmt, depth+1) + "\n"
			}
			result += indent + "}"
		}
		return result
	case *ir.WhileStmt:
		result := indent + "while (" + fmt.Sprint(v.Cond) + ") {\n"
		for _, stmt := range v.Body.Statements {
			result += renderStmt(stmt, depth+1) + "\n"
		}
		result += indent + "}"
		return result
	case *ir.ForEachStmt:
		result := indent + "for (" + typeName(v.VarType) + " " + v.VarName + " : " + fmt.Sprint(v.Expr) + ") {\n"
		for _, stmt := range v.Body.Statements {
			result += renderStmt(stmt, depth+1) + "\n"
		}
		result += indent + "}"
		return result
	case *ir.SwitchStmt:
		result := indent + "switch (" + fmt.Sprint(v.Target) + ") {\n"
		for _, c := range v.Cases {
			for _, val := range c.Values {
				result += indent + "\tcase " + fmt.Sprint(val) + ":\n"
			}
			if c.Body != nil {
				for _, stmt := range c.Body.Statements {
					result += renderStmt(stmt, depth+2) + "\n"
				}
			}
			if !c.Fallthrough && !bodyEndsWithTerminator(c.Body) {
				result += indent + "\t\tbreak;\n"
			}
		}
		if v.Default != nil && len(v.Default.Statements) > 0 {
			result += indent + "\tdefault:\n"
			for _, stmt := range v.Default.Statements {
				result += renderStmt(stmt, depth+2) + "\n"
			}
			if !bodyEndsWithTerminator(v.Default) {
				result += indent + "\t\tbreak;\n"
			}
		}
		result += indent + "}"
		return result
	case *ir.BlockStmt:
		result := indent + "{\n"
		for _, stmt := range v.Block.Statements {
			result += renderStmt(stmt, depth+1) + "\n"
		}
		result += indent + "}"
		return result
	case *ir.TryStmt:
		result := indent + "try "
		if len(v.Resources) > 0 {
			result += "("
			for i, r := range v.Resources {
				if i > 0 {
					result += "; "
				}
				result += typeName(r.VarType) + " " + r.VarName + " = " + fmt.Sprint(r.Init)
			}
			result += ") "
		}
		result += "{\n"
		for _, stmt := range v.Body.Statements {
			result += renderStmt(stmt, depth+1) + "\n"
		}
		result += indent + "}"
		for _, c := range v.Catches {
			result += " catch (" + typeName(c.VarType) + " " + c.VarName + ") {\n"
			for _, stmt := range c.Body.Statements {
				result += renderStmt(stmt, depth+1) + "\n"
			}
			result += indent + "}"
		}
		if v.Finally != nil && len(v.Finally.Statements) > 0 {
			result += " finally {\n"
			for _, stmt := range v.Finally.Statements {
				result += renderStmt(stmt, depth+1) + "\n"
			}
			result += indent + "}"
		}
		return result
	default:
		return indent + fmt.Sprint(s)
	}
}

func bodyEndsWithTerminator(b *ir.Block) bool {
	if b == nil || len(b.Statements) == 0 {
		return false
	}
	switch b.Statements[len(b.Statements)-1].(type) {
	case *ir.ReturnStmt, *ir.ThrowStmt:
		return true
	}
	return false
}

func typeName(t ir.Type) string {
	if t == nil {
		return "void"
	}
	switch v := t.(type) {
	case *ir.PrimitiveType:
		return v.Name
	case *ir.ClassType:
		base := classNameToJava(v.Name)
		if len(v.TypeArgs) == 0 {
			return base
		}
		args := make([]string, len(v.TypeArgs))
		for i, a := range v.TypeArgs {
			args[i] = typeName(a)
		}
		return base + "<" + strings.Join(args, ", ") + ">"
	case *ir.WildcardType:
		if v.Bound == nil {
			return "?"
		}
		if v.Extends {
			return "? extends " + typeName(v.Bound)
		}
		return "? super " + typeName(v.Bound)
	case *ir.TypeVarRef:
		return v.Name
	case *ir.ArrayType:
		return typeName(v.Elem) + "[]"
	default:
		return "Object"
	}
}

func classNameToJava(name string) string {
	switch name {
	case "string", "java.lang.String", "java/lang/String":
		return "String"
	case "object", "java.lang.Object", "java/lang/Object":
		return "Object"
	case "int", "java.lang.Integer", "java/lang/Integer":
		return "int"
	case "long", "java.lang.Long", "java/lang/Long":
		return "long"
	case "float", "java.lang.Float", "java/lang/Float":
		return "float"
	case "double", "java.lang.Double", "java/lang/Double":
		return "double"
	case "bool", "boolean", "java.lang.Boolean", "java/lang/Boolean":
		return "boolean"
	case "char", "java.lang.Character", "java/lang/Character":
		return "char"
	case "byte", "java.lang.Byte", "java/lang/Byte":
		return "byte"
	case "short", "java.lang.Short", "java/lang/Short":
		return "short"
	case "void", "java.lang.Void", "java/lang/Void":
		return "void"
	default:
		name = strings.ReplaceAll(name, "/", ".")
		name = strings.ReplaceAll(name, "$", ".")
		return name
	}
}

var primitiveTypes = map[string]bool{
	"void": true, "boolean": true, "byte": true, "char": true,
	"short": true, "int": true, "long": true, "float": true, "double": true,
	"Object": true, "String": true, "Float": true, "Integer": true,
	"Boolean": true, "Double": true, "Long": true, "Character": true,
	"Byte": true, "Short": true,
}

func collectImports(class *ir.Class) []string {
	seen := map[string]bool{}
	var imports []string

	addImport := func(typeName string) {
		name := strings.ReplaceAll(typeName, "/", ".")
		name = strings.ReplaceAll(name, "$", ".")
		if primitiveTypes[name] {
			return
		}
		if name == "java.lang.Object" || strings.HasPrefix(name, "java.lang.") {
			return
		}
		if strings.HasSuffix(name, "[]") {
			name = name[:len(name)-2]
		}
		if class.Package != "" {
			prefix := class.Package + "."
			if strings.HasPrefix(name, prefix) {
				return
			}
		}
		if seen[name] {
			return
		}
		seen[name] = true
		imports = append(imports, name)
	}

	var walkType func(t ir.Type)
	walkType = func(t ir.Type) {
		switch v := t.(type) {
		case *ir.ClassType:
			addImport(v.Name)
			for _, a := range v.TypeArgs {
				walkType(a)
			}
		case *ir.WildcardType:
			if v.Bound != nil {
				walkType(v.Bound)
			}
		case *ir.ArrayType:
			walkType(v.Elem)
		}
	}

	var walkStmt func(s ir.Stmt)

	var walkExpr func(e ir.Expr)
	walkExpr = func(e ir.Expr) {
		if e == nil {
			return
		}
		switch v := e.(type) {
		case *ir.NewExpr:
			addImport(v.Type)
		case *ir.NewArrayExpr:
			walkType(v.ElemType)
		case *ir.ArrayInitExpr:
			walkType(v.ElemType)
			for _, elem := range v.Elems {
				walkExpr(elem)
			}
		case *ir.CastExpr:
			walkType(v.Type)
			walkExpr(v.Expr)
		case *ir.MethodCall:
			walkExpr(v.Object)
			for _, arg := range v.Args {
				walkExpr(arg)
			}
		case *ir.StaticMethodCall:
			addImport(v.Class)
			for _, arg := range v.Args {
				walkExpr(arg)
			}
		case *ir.FieldAccess:
			walkExpr(v.Object)
		case *ir.BinaryExpr:
			walkExpr(v.Left)
			walkExpr(v.Right)
		case *ir.UnaryExpr:
			walkExpr(v.Expr)
		case *ir.TernaryExpr:
			walkExpr(v.Cond)
			walkExpr(v.TrueExpr)
			walkExpr(v.FalseExpr)
		case *ir.ArrayAccess:
			walkExpr(v.Array)
			walkExpr(v.Index)
		case *ir.MethodRefExpr:
			addImport(v.ClassName)
		case *ir.LambdaExpr:
			if v.Body != nil {
				for _, stmt := range v.Body.Statements {
					walkStmt(stmt)
				}
			}
		}
	}

	walkStmt = func(s ir.Stmt) {
		if s == nil {
			return
		}
		switch v := s.(type) {
		case *ir.VarDeclStmt:
			walkType(v.Type)
			walkExpr(v.Init)
		case *ir.AssignStmt:
			walkExpr(v.Value)
		case *ir.ReturnStmt:
			walkExpr(v.Value)
		case *ir.IfStmt:
			walkExpr(v.Cond)
			if v.Then != nil {
				for _, stmt := range v.Then.Statements {
					walkStmt(stmt)
				}
			}
			if v.Else != nil {
				for _, stmt := range v.Else.Statements {
					walkStmt(stmt)
				}
			}
		case *ir.WhileStmt:
			walkExpr(v.Cond)
			if v.Body != nil {
				for _, stmt := range v.Body.Statements {
					walkStmt(stmt)
				}
			}
		case *ir.ForEachStmt:
			walkType(v.VarType)
			walkExpr(v.Expr)
			if v.Body != nil {
				for _, stmt := range v.Body.Statements {
					walkStmt(stmt)
				}
			}
		case *ir.ExprStmt:
			walkExpr(v.Expr)
		case *ir.TryStmt:
			for _, r := range v.Resources {
				walkType(r.VarType)
				if r.Init != nil {
					walkExpr(r.Init)
				}
			}
			if v.Body != nil {
				for _, stmt := range v.Body.Statements {
					walkStmt(stmt)
				}
			}
			for _, c := range v.Catches {
				walkType(c.VarType)
				if c.Body != nil {
					for _, stmt := range c.Body.Statements {
						walkStmt(stmt)
					}
				}
			}
		}
	}

	for _, tp := range class.TypeParams {
		for _, b := range tp.Bounds {
			walkType(b)
		}
	}
	for _, field := range class.Fields {
		walkType(field.Type)
	}
	for _, method := range class.Methods {
		walkType(method.ReturnType)
		for _, param := range method.Params {
			walkType(param.Type)
		}
		if method.Body != nil {
			for _, stmt := range method.Body.Statements {
				walkStmt(stmt)
			}
		}
	}

	sort.Strings(imports)
	return imports
}

const javaTemplate = `{{- if .Package}}package {{.Package}};

{{end}}{{- if .Imports}}
{{- range .Imports}}import {{.}};
{{end}}
{{end}}{{- if .Access.IsPublic}}public {{end -}}
{{- if .Access.IsAbstract}}abstract {{end -}}
{{- if .Access.IsFinal}}final {{end -}}
{{classKind .Access}} {{.Name}}{{typeParams .TypeParams}}{{- if .SuperClass}} extends {{jtype .SuperClass}}{{end -}}
{{- if .Interfaces}} implements {{range $i, $iface := .Interfaces}}{{if $i}}, {{end}}{{jtype $iface}}{{end}}{{end}} {

{{- range .Fields}}
	{{acc .Access}}{{fmod .Access}}{{typeName .Type}} {{.Name}};
{{- end}}
{{- range .Methods}}
{{- if eq .Name "<init>"}}
	{{acc .Access}}{{$.Name}}({{params .Params}}) {
		super();
{{- if .Body}}{{range .Body.Statements}}{{- if not (isReturnVoid .)}}
		{{.}}{{- end}}{{- end}}{{- end}}
	}
{{- else if eq .Name "<clinit>"}}
	static {
{{- if .Body}}{{range .Body.Statements}}{{- if not (isReturnVoid .)}}
		{{.}}{{- end}}{{- end}}{{- end}}
	}
{{- else}}
	{{acc .Access}}{{mmod .Access}}{{typeName .ReturnType}} {{.Name}}({{params .Params}}) {
{{- if .Body}}{{range .Body.Statements}}
{{renderStmt .}}{{- end}}{{- else}}
		// TODO{{- end}}
	}
{{- end}}
{{- end}}
}
`
