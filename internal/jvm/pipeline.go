package jvm

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"strings"

	"github.com/destruct/destruct/internal/ir"
)

// typeParamNames is keyed by ParsedType.Base's OWN spelling for each
// primitive (see parseTypeAtIndex in descriptors.go) - NOT Java's own
// primitive keywords, which don't all match: 'Z' (boolean) parses to
// Base "bool", and 'B' (byte) parses to Base "sbyte", so a "boolean"/
// "byte" key here would silently never match and fall through to the
// generic derivation below instead.
var typeParamNames = map[string]string{
	"bool":   "flag",
	"sbyte":  "b",
	"char":   "c",
	"short":  "s",
	"int":    "i",
	"long":   "l",
	"float":  "f",
	"double": "d",
}

// classParamNames is keyed by a reference type's full internal (slash-
// separated) class name, matching ParsedType.Base's own format for a
// non-primitive parameter - e.g. "java/lang/Thread", never the bare
// "Thread" or the dotted "java.lang.Thread". "java/lang/Class" maps to
// "clazz" specifically to avoid colliding with the reserved word
// "class" that inferParamName's own generic derivation would otherwise
// produce (lowercasing "Class" - see below); every other name here is
// just a nicer synthesized name than the generic fallback would give.
var classParamNames = map[string]string{
	"java/lang/Thread":     "thread",
	"java/lang/String":     "str",
	"java/lang/Object":     "obj",
	"java/lang/Class":      "clazz",
	"java/lang/Integer":    "value",
	"java/lang/Boolean":    "value",
	"java/util/List":       "list",
	"java/util/Map":        "map",
	"java/util/Set":        "set",
	"java/util/Collection": "coll",
	"java/util/Iterator":   "iter",
}

func inferParamName(p ParsedType, idx int) string {
	if p.IsArray {
		return fmt.Sprintf("arr%d", idx)
	}
	if name, ok := typeParamNames[p.Base]; ok {
		return name
	}
	if name, ok := classParamNames[p.Base]; ok {
		return name
	}
	simpleName := p.Base
	if idx := strings.LastIndex(simpleName, "/"); idx >= 0 {
		simpleName = simpleName[idx+1:]
	}
	if idx := strings.LastIndex(simpleName, "$"); idx >= 0 {
		simpleName = simpleName[idx+1:]
	}
	simpleName = strings.ToLower(simpleName[:1]) + simpleName[1:]
	if simpleName == "" {
		return fmt.Sprintf("arg%d", idx)
	}
	return simpleName
}

func DecompileClassFile(path string) (*ir.Program, error) {
	cf, err := ParseClassFile(path)
	if err != nil {
		return nil, err
	}

	return decompileClassFile(cf)
}

func DecompileJAR(path string) (*ir.Program, error) {
	classes, err := ReadJAR(path)
	if err != nil {
		return nil, err
	}

	program := &ir.Program{}

	for _, cf := range classes {
		p, err := decompileClassFile(cf)
		if err != nil {
			continue
		}
		program.Classes = append(program.Classes, p.Classes...)
	}

	return program, nil
}

// maxClassFileSize bounds how large a single .class entry inside a .jar is
// allowed to be before DecompileJARStreaming refuses to read it into memory.
// Real-world .class files are at most a few MB; this exists as a safety net
// against a corrupt or adversarial zip entry (e.g. a bogus/huge uncompressed
// size, or a decompression-bomb-style entry) rather than a limit expected to
// ever be hit in practice.
const maxClassFileSize = 256 * 1024 * 1024 // 256 MiB

// CountClassEntries returns how many .class entries (outside META-INF) a
// .jar contains, without reading or parsing any of them. This is cheap -
// zip.OpenReader already has the central directory in memory - and lets
// callers show "N / total" progress before streaming begins.
func CountClassEntries(path string) (int, error) {
	r, err := zip.OpenReader(path)
	if err != nil {
		return 0, err
	}
	defer r.Close()

	n := 0
	for _, f := range r.File {
		if strings.HasSuffix(f.Name, ".class") && !strings.Contains(f.Name, "META-INF") {
			n++
		}
	}
	return n, nil
}

// SkipReason describes why one .jar entry was not decompiled.
type SkipReason int

const (
	SkipReasonTooLarge SkipReason = iota
	SkipReasonOpenFailed
	SkipReasonReadFailed
	SkipReasonParseFailed
	SkipReasonDecompileFailed
	SkipReasonPanic
)

func (r SkipReason) String() string {
	switch r {
	case SkipReasonTooLarge:
		return "entry too large"
	case SkipReasonOpenFailed:
		return "could not open entry"
	case SkipReasonReadFailed:
		return "could not read entry"
	case SkipReasonParseFailed:
		return "could not parse class file"
	case SkipReasonDecompileFailed:
		return "could not decompile class"
	case SkipReasonPanic:
		return "internal error while processing entry"
	default:
		return "unknown"
	}
}

// DecompileJARStreaming processes a .jar one .class entry at a time: for
// each entry it reads only that entry's bytes, parses it, decompiles it,
// invokes onClass with the resulting single-class *ir.Program, and then
// discards everything for that entry (raw bytes, constant pool, parsed
// bytecode, AST) before moving to the next one.
//
// Unlike DecompileJAR/ReadJAR, this never holds more than one class file's
// worth of data in memory at a time, which is what makes it safe to run on
// large real-world .jar files (tens of thousands of classes) in
// memory-constrained environments such as a phone. Callers that need
// per-class handling (writing a .java file immediately, for example)
// should use this instead of DecompileJAR.
//
// A malformed/unusual entry - and a panic recovered from parsing,
// decompiling it, or from onClass itself - is reported through onSkip (if
// non-nil) with the entry's name and a reason, and then iteration
// continues with the next entry rather than aborting the whole archive.
// onSkip may be nil if the caller doesn't care about per-entry failures.
//
// If onClass returns an error, that is treated the same as any other
// per-entry failure (reported via onSkip, iteration continues) rather than
// aborting the whole run - a single class that fails to generate should
// not cost the rest of a large .jar.
func DecompileJARStreaming(path string, onClass func(cf *ClassFile, prog *ir.Program) error, onSkip func(entryName string, reason SkipReason, err error)) error {
	r, err := zip.OpenReader(path)
	if err != nil {
		return err
	}
	defer r.Close()

	for _, f := range r.File {
		if !strings.HasSuffix(f.Name, ".class") || strings.Contains(f.Name, "META-INF") {
			continue
		}
		decompileJAREntryStreaming(f, onClass, onSkip)
	}

	return nil
}

// decompileJAREntryStreaming handles a single zip entry in its own scope so
// that every intermediate (the open file handle, the raw class bytes, the
// parsed *ClassFile, the decompiled *ir.Program) becomes unreachable and
// collectible as soon as this call returns, rather than staying referenced
// for the duration of the whole archive's processing.
//
// It also recovers from any panic raised while parsing, decompiling, or in
// onClass, so that one malformed or unusually-shaped class (a common thing
// in obfuscated/hostile real-world jars) can never take down decompilation
// of the rest of the archive.
func decompileJAREntryStreaming(f *zip.File, onClass func(cf *ClassFile, prog *ir.Program) error, onSkip func(entryName string, reason SkipReason, err error)) {
	skip := func(reason SkipReason, err error) {
		if onSkip != nil {
			onSkip(f.Name, reason, err)
		}
	}

	defer func() {
		if r := recover(); r != nil {
			skip(SkipReasonPanic, fmt.Errorf("%v", r))
		}
	}()

	if f.UncompressedSize64 > maxClassFileSize {
		skip(SkipReasonTooLarge, nil)
		return
	}

	rc, err := f.Open()
	if err != nil {
		skip(SkipReasonOpenFailed, err)
		return
	}
	defer rc.Close()

	data, err := io.ReadAll(io.LimitReader(rc, maxClassFileSize+1))
	if err != nil {
		skip(SkipReasonReadFailed, err)
		return
	}
	if len(data) > maxClassFileSize {
		skip(SkipReasonTooLarge, nil)
		return
	}

	cf, err := ParseClassFileFromBytes(data)
	if err != nil {
		skip(SkipReasonParseFailed, err)
		return
	}
	data = nil // allow the raw bytes to be collected before decompiling

	prog, err := decompileClassFile(cf)
	if err != nil {
		skip(SkipReasonDecompileFailed, err)
		return
	}

	if err := onClass(cf, prog); err != nil {
		skip(SkipReasonDecompileFailed, err)
	}
}

func ReadJAR(path string) ([]*ClassFile, error) {
	r, err := zip.OpenReader(path)
	if err != nil {
		return nil, err
	}
	defer r.Close()

	var classes []*ClassFile
	for _, f := range r.File {
		if strings.HasSuffix(f.Name, ".class") && !strings.Contains(f.Name, "META-INF") {
			rc, err := f.Open()
			if err != nil {
				continue
			}
			data, err := io.ReadAll(rc)
			rc.Close()
			if err != nil {
				continue
			}

			cf, err := ParseClassFileFromBytes(data)
			if err != nil {
				continue
			}
			classes = append(classes, cf)
		}
	}

	return classes, nil
}

func ParseClassFileFromBytes(data []byte) (*ClassFile, error) {
	return ParseClassFileFromReader(bytes.NewReader(data))
}

func decompileClassFile(cf *ClassFile) (*ir.Program, error) {
	classSimpleName := cf.GetSimpleClassName()
	javaClass := classNameToJavaName(classSimpleName)

	pkg := cf.GetPackageName()

	classDecl := &ir.Class{
		Name:    classSimpleName,
		Package: pkg,
		Access:  ir.AccessFlags(cf.AccessFlags),
	}

	if super := cf.GetSuperClassName(); super != "" && super != "java/lang/Object" {
		classDecl.SuperClass = super
	}
	classDecl.Interfaces = cf.GetInterfaceNames()

	if sig, ok := findSignatureAttr(cf, cf.Attributes); ok {
		if typeParams, ok := parseClassSignature(sig); ok {
			classDecl.TypeParams = typeParams
		}
	}

	for _, field := range cf.Fields {
		fieldDecl := ir.Field{
			Name:   cf.GetUTF8(field.NameIndex),
			Access: ir.AccessFlags(field.AccessFlags),
		}
		fieldDecl.Type = jvmDescToIRType(cf.GetUTF8(field.DescriptorIndex))
		if sig, ok := findSignatureAttr(cf, field.Attributes); ok {
			if genericType, ok := parseFieldSignature(sig); ok {
				fieldDecl.Type = genericType
			}
		}
		classDecl.Fields = append(classDecl.Fields, &fieldDecl)
	}

	for i, method := range cf.Methods {
		methodDecl := ir.Method{
			Name:   sanitizeMethodName(cf.GetUTF8(method.NameIndex)),
			Access: ir.AccessFlags(method.AccessFlags),
		}
		params, ret := ParseDescriptor(cf.GetUTF8(method.DescriptorIndex))
		methodDecl.ReturnType = jvmParsedToIRType(ret)

		// Prefer the real generic parameter/return types from the
		// Signature attribute when present AND its parameter count
		// matches the erased descriptor's - a mismatch means this
		// method has synthetic parameters the generic signature never
		// describes (a captured outer-class instance on an inner
		// class's constructor, or the implicit name/ordinal on an enum
		// constructor), and mixing resolved generic types with erased
		// ones by raw position in that case would silently attach the
		// wrong type to the wrong parameter - falling back to fully
		// erased types for the whole method is the only always-correct
		// choice.
		var sigParamTypes []ir.Type
		var sigRetType ir.Type
		hasSigTypes := false
		if sig, ok := findSignatureAttr(cf, method.Attributes); ok {
			if sp, sr, ok := parseMethodSignature(sig); ok && len(sp) == len(params) {
				sigParamTypes, sigRetType, hasSigTypes = sp, sr, true
			}
		}
		if hasSigTypes {
			methodDecl.ReturnType = sigRetType
		}

		isStatic := method.AccessFlags&0x0008 != 0
		paramNames := buildParamNames(cf, i)

		slot := uint16(0)
		if !isStatic {
			slot = 1
		}
		for pi, p := range params {
			paramType := jvmParsedToIRType(p)
			if hasSigTypes {
				paramType = sigParamTypes[pi]
			}
			methodDecl.Params = append(methodDecl.Params, &ir.Param{
				Name: paramNames[slot],
				Type: paramType,
			})
			slot++
			if p.Base == "long" || p.Base == "double" {
				slot++
			}
		}
		code, err := cf.ParseCodeAttribute(i)
		if err == nil && code != nil {
			methodDecl.Body = decompileCode(cf, i, code, classSimpleName)
			if strings.HasPrefix(methodDecl.Name, "lambda$") {
				marker := &ir.ExprStmt{Expr: &ir.StringLit{Value: "DESTRUCT: this is a compiler-generated lambda body, already shown inline as a lambda expression at each of its call sites above"}}
				methodDecl.Body.Statements = append([]ir.Stmt{marker}, methodDecl.Body.Statements...)
			}
		}
		classDecl.Methods = append(classDecl.Methods, &methodDecl)
	}

	program := &ir.Program{
		Classes: []*ir.Class{classDecl},
	}

	_ = javaClass
	return program, nil
}
