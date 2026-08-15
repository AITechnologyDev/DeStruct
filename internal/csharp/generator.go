package csharp

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/template"

	"github.com/destruct/destruct/internal/ir"
)

type Options struct {
	OutputDir string
	Project   bool
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

	if g.opts.Project {
		if err := g.generateProject(prog); err != nil {
			return fmt.Errorf("generating project: %w", err)
		}
	}

	return nil
}

func (g *Generator) generateClass(class *ir.Class) error {
	ns := strings.ReplaceAll(class.Package, ".", "/")
	ns = strings.ReplaceAll(ns, "_", ".")

	dir := filepath.Join(g.opts.OutputDir, strings.ToLower(class.Package))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}

	filename := filepath.Join(dir, class.Name+".cs")

	tmpl, err := template.New("class").Funcs(template.FuncMap{
		"accessModifier": func(f ir.AccessFlags) string {
			if f.IsPublic() {
				return "public"
			}
			if f.IsPrivate() {
				return "private"
			}
			if f.IsProtected() {
				return "protected"
			}
			return "internal"
		},
		"typeModifier": func(f ir.AccessFlags) string {
			var mods []string
			if f.IsStatic() {
				mods = append(mods, "static")
			}
			if f.IsFinal() {
				mods = append(mods, "sealed")
			}
			if f.IsAbstract() {
				mods = append(mods, "abstract")
			}
			return strings.Join(mods, " ")
		},
		"fieldModifier": func(f ir.AccessFlags) string {
			var mods []string
			if f.IsStatic() {
				mods = append(mods, "static")
			}
			if f.IsFinal() {
				mods = append(mods, "readonly")
			}
			return strings.Join(mods, " ")
		},
		"methodModifier": func(f ir.AccessFlags) string {
			var mods []string
			if f.IsStatic() {
				mods = append(mods, "static")
			}
			if f.IsFinal() {
				mods = append(mods, "sealed")
			}
			if f.IsAbstract() {
				mods = append(mods, "abstract")
			}
			return strings.Join(mods, " ")
		},
		"formatType": formatType,
		"formatParams": formatParams,
		"join": func(elems []string) string {
			return strings.Join(elems, ", ")
		},
		"methodName": func(name string) string {
			if name == "<init>" {
				return ""
			}
			if name == "<clinit>" {
				return "static_constructor"
			}
			return name
		},
		"isConstructor": func(name string) bool {
			return name == "<init>"
		},
		"classToCSharp": classToCSharp,
	}).Parse(classTemplate)
	if err != nil {
		return err
	}

	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	data := struct {
		Package string
		Class   *ir.Class
	}{
		Package: class.Package,
		Class:   class,
	}

	return tmpl.Execute(f, data)
}

func (g *Generator) generateProject(prog *ir.Program) error {
	tmpl, err := template.New("csproj").Parse(csprojTemplate)
	if err != nil {
		return err
	}

	filename := filepath.Join(g.opts.OutputDir, "DecompiledProject.csproj")
	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	return tmpl.Execute(f, nil)
}

func formatType(t ir.Type) string {
	if t == nil {
		return "void"
	}

	switch v := t.(type) {
	case *ir.PrimitiveType:
		return primitiveToCSharp(v.Name)
	case *ir.ClassType:
		return classToCSharp(v.Name)
	case *ir.ArrayType:
		return formatType(v.Elem) + "[]"
	default:
		return "object"
	}
}

func primitiveToCSharp(name string) string {
	switch name {
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
		return "bool"
	case "void":
		return "void"
	default:
		return name
	}
}

func classToCSharp(name string) string {
	switch name {
	case "java.lang.String", "java/lang/String":
		return "string"
	case "java.lang.Object", "java/lang/Object":
		return "object"
	case "java.lang.Integer", "java/lang/Integer":
		return "int"
	case "java.lang.Long", "java/lang/Long":
		return "long"
	case "java.lang.Float", "java/lang/Float":
		return "float"
	case "java.lang.Double", "java/lang/Double":
		return "double"
	case "java.lang.Boolean", "java/lang/Boolean":
		return "bool"
	case "java.lang.Character", "java/lang/Character":
		return "char"
	case "java.lang.Byte", "java/lang/Byte":
		return "byte"
	case "java.lang.Short", "java/lang/Short":
		return "short"
	case "java.lang.Void", "java/lang/Void":
		return "void"
	case "java.lang.StringBuilder", "java/lang/StringBuilder":
		return "StringBuilder"
	case "java.lang.System", "java/lang/System":
		return "System"
	case "java.lang.Exception", "java/lang/Exception":
		return "Exception"
	case "java.lang.Throwable", "java/lang/Throwable":
		return "Exception"
	case "java.lang.RuntimeException", "java/lang/RuntimeException":
		return "Exception"
	case "java.util.List", "java/util/List":
		return "IList"
	case "java.util.ArrayList", "java/util/ArrayList":
		return "List"
	case "java.util.Map", "java/util/Map":
		return "IDictionary"
	case "java.util.HashMap", "java/util/HashMap":
		return "Dictionary"
	case "java.util.Set", "java/util/Set":
		return "ISet"
	case "java.util.HashSet", "java/util/HashSet":
		return "HashSet"
	case "java.util.Iterator", "java/util/Iterator":
		return "IEnumerator"
	case "java.lang.Iterable", "java/lang/Iterable":
		return "IEnumerable"
	case "java.lang.Comparable", "java/lang/Comparable":
		return "IComparable"
	case "java.lang.Runnable", "java/lang/Runnable":
		return "Action"
	case "java.io.InputStream", "java/io/InputStream":
		return "Stream"
	case "java.io.OutputStream", "java/io/OutputStream":
		return "Stream"
	case "java.io.Reader", "java/io/Reader":
		return "TextReader"
	case "java.io.Writer", "java/io/Writer":
		return "TextWriter"
	case "java.lang.Thread", "java/lang/Thread":
		return "Thread"
	case "java.lang.AutoCloseable", "java/lang/AutoCloseable":
		return "IDisposable"
	case "java.lang.Cloneable", "java/lang/Cloneable":
		return "ICloneable"
	case "java.lang.Comparable[]", "java/lang/Comparable[]":
		return "IComparable[]"
	default:
		name = strings.ReplaceAll(name, "/", ".")
		name = strings.ReplaceAll(name, "$", ".")
		return name
	}
}

func formatParams(params []*ir.Param) string {
	var parts []string
	for i, p := range params {
		parts = append(parts, fmt.Sprintf("%s arg%d", formatType(p.Type), i))
	}
	return strings.Join(parts, ", ")
}

const classTemplate = `{{if .Package}}namespace {{.Package}}
{{end}}
{{if .Class.Access.IsInterface}}	[Interface]
{{end}}{{if .Class.Access.IsEnum}}	[Flags]
{{end}}	{{accessModifier .Class.Access}} {{typeModifier .Class.Access}} {{if .Class.Access.IsInterface}}interface{{else if .Class.Access.IsEnum}}enum{{else}}class{{end}} {{.Class.Name}}{{if .Class.SuperClass}} : {{classToCSharp .Class.SuperClass}}{{if .Class.Interfaces}}, {{join .Class.Interfaces}}{{end}}{{else if .Class.Interfaces}} : {{join .Class.Interfaces}}{{end}}
	{
{{range .Class.Fields}}		{{accessModifier .Access}} {{fieldModifier .Access}} {{formatType .Type}} {{.Name}};
{{end}}{{range .Class.Methods}}
{{if isConstructor .Name}}		{{accessModifier .Access}} {{$.Class.Name}}({{formatParams .Params}})
		{
			// TODO: implement constructor
		}
{{else}}		{{accessModifier .Access}} {{methodModifier .Access}} {{formatType .ReturnType}} {{methodName .Name}}({{formatParams .Params}})
		{
{{if .Body}}{{range .Body.Statements}}			{{.}}
{{end}}{{else}}			// TODO: implement method
{{end}}		}
{{end}}{{end}}	}
`

const csprojTemplate = `<Project Sdk="Microsoft.NET.Sdk">

  <PropertyGroup>
    <TargetFramework>net8.0</TargetFramework>
    <ImplicitUsings>enable</ImplicitUsings>
    <Nullable>enable</Nullable>
    <RootNamespace>Decompiled</RootNamespace>
  </PropertyGroup>

</Project>
`
