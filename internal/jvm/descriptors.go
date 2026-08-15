package jvm

import (
	"fmt"
	"strings"
)

type DescriptorType int

const (
	DescByte DescriptorType = iota
	DescChar
	DescDouble
	DescFloat
	DescInt
	DescLong
	DescShort
	DescBoolean
	DescVoid
	DescObject
	DescArray
)

type ParsedType struct {
	Base     string
	ArrayDim int
	IsArray  bool
}

func ParseDescriptor(desc string) (params []ParsedType, ret ParsedType) {
	if len(desc) == 0 || desc[0] != '(' {
		return nil, parseSingleType(desc)
	}

	paramStr := desc[1:strings.Index(desc, ")")]
	retStr := desc[strings.Index(desc, ")")+1:]

	params = parseParamList(paramStr)
	ret = parseSingleType(retStr)
	return
}

func parseParamList(s string) []ParsedType {
	var result []ParsedType
	i := 0
	for i < len(s) {
		t, consumed := parseTypeAtIndex(s, i)
		result = append(result, t)
		i += consumed
	}
	return result
}

func parseTypeAtIndex(s string, start int) (ParsedType, int) {
	if start >= len(s) {
		return ParsedType{Base: "void"}, 1
	}

	switch s[start] {
	case 'B':
		return ParsedType{Base: "sbyte"}, 1
	case 'C':
		return ParsedType{Base: "char"}, 1
	case 'D':
		return ParsedType{Base: "double"}, 1
	case 'F':
		return ParsedType{Base: "float"}, 1
	case 'I':
		return ParsedType{Base: "int"}, 1
	case 'J':
		return ParsedType{Base: "long"}, 1
	case 'S':
		return ParsedType{Base: "short"}, 1
	case 'Z':
		return ParsedType{Base: "bool"}, 1
	case 'V':
		return ParsedType{Base: "void"}, 1
	case 'L':
		end := strings.Index(s[start:], ";")
		if end == -1 {
			return ParsedType{Base: s[start+1:]}, len(s) - start
		}
		name := s[start+1 : start+end]
		return ParsedType{Base: name}, end + 1
	case '[':
		t, consumed := parseTypeAtIndex(s, start+1)
		t.ArrayDim++
		t.IsArray = true
		return t, consumed + 1
	default:
		return ParsedType{Base: "object"}, 1
	}
}

func parseSingleType(s string) ParsedType {
	if len(s) == 0 {
		return ParsedType{Base: "void"}
	}
	t, _ := parseTypeAtIndex(s, 0)
	return t
}

func DescriptorToCSharpType(desc string) string {
	t := parseSingleType(desc)
	return csharpTypeName(t)
}

func csharpTypeName(t ParsedType) string {
	base := ""
	switch t.Base {
	case "byte", "sbyte":
		base = "byte"
	case "char":
		base = "char"
	case "double":
		base = "double"
	case "float":
		base = "float"
	case "int":
		base = "int"
	case "long":
		base = "long"
	case "short":
		base = "short"
	case "bool", "boolean":
		base = "bool"
	case "void":
		base = "void"
	case "java/lang/String", "java.lang.String":
		base = "string"
	case "java/lang/Object", "java.lang.Object":
		base = "object"
	default:
		base = classNameToCSharp(t.Base)
	}

	if t.IsArray {
		for i := 0; i < t.ArrayDim; i++ {
			base += "[]"
		}
	}

	return base
}

func classNameToCSharp(name string) string {
	name = strings.ReplaceAll(name, "/", ".")
	name = strings.ReplaceAll(name, "$", ".")
	return name
}

func MethodDescriptorToCSharp(desc string) (string, string) {
	params, ret := ParseDescriptor(desc)

	var paramTypes []string
	for _, p := range params {
		paramTypes = append(paramTypes, csharpTypeName(p))
	}

	return strings.Join(paramTypes, ", "), csharpTypeName(ret)
}

func (cf *ClassFile) ResolveMethodName(methodIdx int) string {
	if methodIdx >= len(cf.Methods) {
		return ""
	}
	m := cf.Methods[methodIdx]
	return cf.GetUTF8(m.NameIndex)
}

func (cf *ClassFile) ResolveMethodDescriptor(methodIdx int) string {
	if methodIdx >= len(cf.Methods) {
		return ""
	}
	m := cf.Methods[methodIdx]
	return cf.GetUTF8(m.DescriptorIndex)
}

func (cf *ClassFile) ResolveFieldName(fieldIdx int) string {
	if fieldIdx >= len(cf.Fields) {
		return ""
	}
	f := cf.Fields[fieldIdx]
	return cf.GetUTF8(f.NameIndex)
}

func (cf *ClassFile) ResolveFieldDescriptor(fieldIdx int) string {
	if fieldIdx >= len(cf.Fields) {
		return ""
	}
	f := cf.Fields[fieldIdx]
	return cf.GetUTF8(f.DescriptorIndex)
}

func (cf *ClassFile) GetPackageName() string {
	className := cf.GetThisClassName()
	parts := strings.Split(className, "/")
	if len(parts) > 1 {
		return strings.Join(parts[:len(parts)-1], ".")
	}
	return ""
}

func (cf *ClassFile) GetSimpleClassName() string {
	className := cf.GetThisClassName()
	parts := strings.Split(className, "/")
	return parts[len(parts)-1]
}

func (cf *ClassFile) GetClassFullName() string {
	return classNameToCSharp(cf.GetThisClassName())
}

func (cf *ClassFile) GetSuperClassFullName() string {
	super := cf.GetSuperClassName()
	if super == "" {
		return ""
	}
	return classNameToCSharp(super)
}

func (cf *ClassFile) GetInterfaceFullNames() []string {
	names := cf.GetInterfaceNames()
	result := make([]string, len(names))
	for i, name := range names {
		result[i] = classNameToCSharp(name)
	}
	return result
}

func (cf *ClassFile) IsAbstract() bool {
	return cf.AccessFlags&0x0400 != 0
}

func (cf *ClassFile) IsInterface() bool {
	return cf.AccessFlags&0x0200 != 0
}

func (cf *ClassFile) IsEnum() bool {
	return cf.AccessFlags&0x4000 != 0
}

func (cf *ClassFile) IsStatic() bool {
	return cf.AccessFlags&0x0008 != 0
}

func (cf *ClassFile) IsFinal() bool {
	return cf.AccessFlags&0x0010 != 0
}

func (cf *ClassFile) IsSynthetic() bool {
	return cf.AccessFlags&0x1000 != 0
}

func (cf *ClassFile) GetAccessModifier() string {
	if cf.AccessFlags&0x0001 != 0 {
		return "public"
	}
	if cf.AccessFlags&0x0002 != 0 {
		return "private"
	}
	if cf.AccessFlags&0x0004 != 0 {
		return "protected"
	}
	return "internal"
}

func MethodAccessModifier(flags uint16) string {
	if flags&0x0001 != 0 {
		return "public"
	}
	if flags&0x0002 != 0 {
		return "private"
	}
	if flags&0x0004 != 0 {
		return "protected"
	}
	return "internal"
}

func MethodModifiers(flags uint16) string {
	var mods []string
	if flags&0x0008 != 0 {
		mods = append(mods, "static")
	}
	if flags&0x0010 != 0 {
		mods = append(mods, "sealed")
	}
	if flags&0x0400 != 0 {
		mods = append(mods, "abstract")
	}
	if flags&0x0800 != 0 {
		mods = append(mods, "extern")
	}
	return strings.Join(mods, " ")
}

func FieldAccessModifier(flags uint16) string {
	return MethodAccessModifier(flags)
}

func FieldModifiers(flags uint16) string {
	var mods []string
	if flags&0x0008 != 0 {
		mods = append(mods, "static")
	}
	if flags&0x0010 != 0 {
		mods = append(mods, "readonly")
	}
	if flags&0x0040 != 0 {
		mods = append(mods, "volatile")
	}
	return strings.Join(mods, " ")
}

func (cf *ClassFile) GetThisName() string {
	return fmt.Sprintf("%s.%s", cf.GetPackageName(), cf.GetSimpleClassName())
}
