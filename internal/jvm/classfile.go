package jvm

import (
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"os"
	"strings"
)

const (
	classMagic = 0xCAFEBABE
)

type ConstantPoolTag byte

const (
	TagUtf8               ConstantPoolTag = 1
	TagInteger            ConstantPoolTag = 3
	TagFloat              ConstantPoolTag = 4
	TagLong               ConstantPoolTag = 5
	TagDouble             ConstantPoolTag = 6
	TagClass              ConstantPoolTag = 7
	TagString             ConstantPoolTag = 8
	TagFieldref           ConstantPoolTag = 9
	TagMethodref          ConstantPoolTag = 10
	TagInterfaceMethodref ConstantPoolTag = 11
	TagNameAndType        ConstantPoolTag = 12
	TagMethodHandle       ConstantPoolTag = 15
	TagMethodType         ConstantPoolTag = 16
	TagDynamic            ConstantPoolTag = 17
	TagInvokeDynamic      ConstantPoolTag = 18
	TagModule             ConstantPoolTag = 19
	TagPackage            ConstantPoolTag = 20
)

type ClassFile struct {
	Magic            uint32
	MinorVersion     uint16
	MajorVersion     uint16
	ConstantPool     []ConstantPoolEntry
	AccessFlags      uint16
	ThisClass        uint16
	SuperClass       uint16
	Interfaces       []uint16
	Fields           []FieldInfo
	Methods          []MethodInfo
	Attributes       []AttributeInfo
	SourceFile       string
}

type ConstantPoolEntry struct {
	Tag  ConstantPoolEntryType
	UTF8 *ConstantUtf8
	Integer *ConstantInteger
	Float *ConstantFloat
	Long *ConstantLong
	Double *ConstantDouble
	Class *ConstantClass
	String *ConstantString
	Fieldref *ConstantFieldref
	Methodref *ConstantMethodref
	InterfaceMethodref *ConstantInterfaceMethodref
	NameAndType *ConstantNameAndType
	MethodHandle *ConstantMethodHandle
	MethodType *ConstantMethodType
	Dynamic *ConstantDynamic
	InvokeDynamic *ConstantInvokeDynamic
	Module *ConstantModule
	Package *ConstantPackage
}

type ConstantUtf8 struct {
	Value string
}

type ConstantInteger struct {
	Value int32
}

type ConstantFloat struct {
	Value float32
}

type ConstantLong struct {
	Value int64
}

type ConstantDouble struct {
	Value float64
}

type ConstantClass struct {
	NameIndex uint16
}

type ConstantString struct {
	StringIndex uint16
}

type ConstantFieldref struct {
	ClassIndex       uint16
	NameAndTypeIndex uint16
}

type ConstantMethodref struct {
	ClassIndex       uint16
	NameAndTypeIndex uint16
}

type ConstantInterfaceMethodref struct {
	ClassIndex       uint16
	NameAndTypeIndex uint16
}

type ConstantNameAndType struct {
	NameIndex       uint16
	DescriptorIndex uint16
}

type ConstantMethodHandle struct {
	ReferenceKind  byte
	ReferenceIndex uint16
}

type ConstantMethodType struct {
	DescriptorIndex uint16
}

type ConstantDynamic struct {
	BootstrapMethodAttrIndex uint16
	NameAndTypeIndex         uint16
}

type ConstantInvokeDynamic struct {
	BootstrapMethodAttrIndex uint16
	NameAndTypeIndex         uint16
}

type ConstantModule struct {
	NameIndex uint16
}

type ConstantPackage struct {
	NameIndex uint16
}

type ConstantPoolEntryType byte

const (
	CPTypeUtf8               ConstantPoolEntryType = 1
	CPTypeInteger            ConstantPoolEntryType = 3
	CPTypeFloat              ConstantPoolEntryType = 4
	CPTypeLong               ConstantPoolEntryType = 5
	CPTypeDouble             ConstantPoolEntryType = 6
	CPTypeClass              ConstantPoolEntryType = 7
	CPTypeString             ConstantPoolEntryType = 8
	CPTypeFieldref           ConstantPoolEntryType = 9
	CPTypeMethodref          ConstantPoolEntryType = 10
	CPTypeInterfaceMethodref ConstantPoolEntryType = 11
	CPTypeNameAndType        ConstantPoolEntryType = 12
	CPTypeMethodHandle       ConstantPoolEntryType = 15
	CPTypeMethodType         ConstantPoolEntryType = 16
	CPTypeDynamic            ConstantPoolEntryType = 17
	CPTypeInvokeDynamic      ConstantPoolEntryType = 18
	CPTypeModule             ConstantPoolEntryType = 19
	CPTypePackage            ConstantPoolEntryType = 20
)

type FieldInfo struct {
	AccessFlags uint16
	NameIndex   uint16
	DescriptorIndex uint16
	Attributes  []AttributeInfo
}

type MethodInfo struct {
	AccessFlags uint16
	NameIndex   uint16
	DescriptorIndex uint16
	Attributes  []AttributeInfo
}

type AttributeInfo struct {
	NameIndex uint16
	Data      []byte
}

type CodeAttribute struct {
	MaxStack       uint16
	MaxLocals      uint16
	Code           []byte
	ExceptionTable []ExceptionEntry
	Attributes     []AttributeInfo
}

type ExceptionEntry struct {
	StartPC   uint16
	EndPC     uint16
	HandlerPC uint16
	CatchType uint16
}

type LineNumberEntry struct {
	StartPC   uint16
	LineNumber uint16
}

type LocalVariableEntry struct {
	StartPC         uint16
	Length          uint16
	NameIndex       uint16
	DescriptorIndex uint16
	Index           uint16
}

type reader struct {
	r   io.Reader
	buf []byte
}

func newReader(r io.Reader) *reader {
	return &reader{r: r}
}

func (r *reader) readByte() (byte, error) {
	b := make([]byte, 1)
	if _, err := io.ReadFull(r.r, b); err != nil {
		return 0, err
	}
	return b[0], nil
}

func (r *reader) readUint16() (uint16, error) {
	b := make([]byte, 2)
	if _, err := io.ReadFull(r.r, b); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint16(b), nil
}

func (r *reader) readUint32() (uint32, error) {
	b := make([]byte, 4)
	if _, err := io.ReadFull(r.r, b); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(b), nil
}

func (r *reader) readBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(r.r, b); err != nil {
		return nil, err
	}
	return b, nil
}

func ParseClassFile(filename string) (*ClassFile, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	return parseClassFile(f)
}

func ParseClassFileFromReader(r io.Reader) (*ClassFile, error) {
	return parseClassFile(r)
}

func parseClassFile(r io.Reader) (*ClassFile, error) {
	cr := newReader(r)
	cf := &ClassFile{}

	var err error
	cf.Magic, err = cr.readUint32()
	if err != nil {
		return nil, fmt.Errorf("reading magic: %w", err)
	}
	if cf.Magic != classMagic {
		return nil, fmt.Errorf("invalid class file magic: 0x%08X (expected 0xCAFEBABE)", cf.Magic)
	}

	cf.MinorVersion, err = cr.readUint16()
	if err != nil {
		return nil, fmt.Errorf("reading minor version: %w", err)
	}

	cf.MajorVersion, err = cr.readUint16()
	if err != nil {
		return nil, fmt.Errorf("reading major version: %w", err)
	}

	cpCount, err := cr.readUint16()
	if err != nil {
		return nil, fmt.Errorf("reading constant pool count: %w", err)
	}

	cf.ConstantPool, err = parseConstantPool(cr, cpCount)
	if err != nil {
		return nil, fmt.Errorf("parsing constant pool: %w", err)
	}

	cf.AccessFlags, err = cr.readUint16()
	if err != nil {
		return nil, fmt.Errorf("reading access flags: %w", err)
	}

	cf.ThisClass, err = cr.readUint16()
	if err != nil {
		return nil, fmt.Errorf("reading this class: %w", err)
	}

	cf.SuperClass, err = cr.readUint16()
	if err != nil {
		return nil, fmt.Errorf("reading super class: %w", err)
	}

	ifaceCount, err := cr.readUint16()
	if err != nil {
		return nil, fmt.Errorf("reading interfaces count: %w", err)
	}

	cf.Interfaces = make([]uint16, ifaceCount)
	for i := uint16(0); i < ifaceCount; i++ {
		cf.Interfaces[i], err = cr.readUint16()
		if err != nil {
			return nil, fmt.Errorf("reading interface %d: %w", i, err)
		}
	}

	fieldCount, err := cr.readUint16()
	if err != nil {
		return nil, fmt.Errorf("reading fields count: %w", err)
	}

	cf.Fields, err = parseFieldInfos(cr, fieldCount, cf.ConstantPool)
	if err != nil {
		return nil, fmt.Errorf("parsing fields: %w", err)
	}

	methodCount, err := cr.readUint16()
	if err != nil {
		return nil, fmt.Errorf("reading methods count: %w", err)
	}

	cf.Methods, err = parseMethodInfos(cr, methodCount, cf.ConstantPool)
	if err != nil {
		return nil, fmt.Errorf("parsing methods: %w", err)
	}

	attrCount, err := cr.readUint16()
	if err != nil {
		return nil, fmt.Errorf("reading attributes count: %w", err)
	}

	cf.Attributes, err = parseAttributes(cr, attrCount, cf.ConstantPool)
	if err != nil {
		return nil, fmt.Errorf("parsing attributes: %w", err)
	}

	for _, attr := range cf.Attributes {
		if cf.ConstantPool[attr.NameIndex].Tag == CPTypeUtf8 &&
			cf.ConstantPool[attr.NameIndex].UTF8.Value == "SourceFile" && len(attr.Data) >= 2 {
			sfIdx := binary.BigEndian.Uint16(attr.Data[:2])
			if cf.ConstantPool[sfIdx].Tag == CPTypeUtf8 {
				cf.SourceFile = cf.ConstantPool[sfIdx].UTF8.Value
			}
		}
	}

	return cf, nil
}

func parseConstantPool(cr *reader, count uint16) ([]ConstantPoolEntry, error) {
	pool := make([]ConstantPoolEntry, count)
	i := uint16(1)
	for i < count {
		tag, err := cr.readByte()
		if err != nil {
			return nil, fmt.Errorf("reading CP tag at index %d: %w", i, err)
		}

		entry := ConstantPoolEntry{Tag: ConstantPoolEntryType(tag)}

		switch ConstantPoolEntryType(tag) {
		case CPTypeUtf8:
			length, err := cr.readUint16()
			if err != nil {
				return nil, err
			}
			data, err := cr.readBytes(int(length))
			if err != nil {
				return nil, err
			}
			entry.UTF8 = &ConstantUtf8{Value: decodeModifiedUTF8(data)}

		case CPTypeInteger:
			v, err := cr.readUint32()
			if err != nil {
				return nil, err
			}
			entry.Integer = &ConstantInteger{Value: int32(v)}

		case CPTypeFloat:
			v, err := cr.readUint32()
			if err != nil {
				return nil, err
			}
			entry.Float = &ConstantFloat{Value: math.Float32frombits(v)}

		case CPTypeLong:
			high, err := cr.readUint32()
			if err != nil {
				return nil, err
			}
			low, err := cr.readUint32()
			if err != nil {
				return nil, err
			}
			entry.Long = &ConstantLong{Value: int64(high)<<32 | int64(low)}
			pool[i] = entry
			i++
			pool[i] = ConstantPoolEntry{}
			i++
			continue

		case CPTypeDouble:
			high, err := cr.readUint32()
			if err != nil {
				return nil, err
			}
			low, err := cr.readUint32()
			if err != nil {
				return nil, err
			}
			entry.Double = &ConstantDouble{Value: math.Float64frombits(uint64(high)<<32 | uint64(low))}
			pool[i] = entry
			i++
			pool[i] = ConstantPoolEntry{}
			i++
			continue

		case CPTypeClass:
			idx, err := cr.readUint16()
			if err != nil {
				return nil, err
			}
			entry.Class = &ConstantClass{NameIndex: idx}

		case CPTypeString:
			idx, err := cr.readUint16()
			if err != nil {
				return nil, err
			}
			entry.String = &ConstantString{StringIndex: idx}

		case CPTypeFieldref, CPTypeMethodref, CPTypeInterfaceMethodref:
			classIdx, err := cr.readUint16()
			if err != nil {
				return nil, err
			}
			natIdx, err := cr.readUint16()
			if err != nil {
				return nil, err
			}
			switch ConstantPoolEntryType(tag) {
			case CPTypeFieldref:
				entry.Fieldref = &ConstantFieldref{ClassIndex: classIdx, NameAndTypeIndex: natIdx}
			case CPTypeMethodref:
				entry.Methodref = &ConstantMethodref{ClassIndex: classIdx, NameAndTypeIndex: natIdx}
			case CPTypeInterfaceMethodref:
				entry.InterfaceMethodref = &ConstantInterfaceMethodref{ClassIndex: classIdx, NameAndTypeIndex: natIdx}
			}

		case CPTypeNameAndType:
			nameIdx, err := cr.readUint16()
			if err != nil {
				return nil, err
			}
			descIdx, err := cr.readUint16()
			if err != nil {
				return nil, err
			}
			entry.NameAndType = &ConstantNameAndType{NameIndex: nameIdx, DescriptorIndex: descIdx}

		case CPTypeMethodHandle:
			kind, err := cr.readByte()
			if err != nil {
				return nil, err
			}
			idx, err := cr.readUint16()
			if err != nil {
				return nil, err
			}
			entry.MethodHandle = &ConstantMethodHandle{ReferenceKind: kind, ReferenceIndex: idx}

		case CPTypeMethodType:
			idx, err := cr.readUint16()
			if err != nil {
				return nil, err
			}
			entry.MethodType = &ConstantMethodType{DescriptorIndex: idx}

		case CPTypeDynamic, CPTypeInvokeDynamic:
			bsmIdx, err := cr.readUint16()
			if err != nil {
				return nil, err
			}
			natIdx, err := cr.readUint16()
			if err != nil {
				return nil, err
			}
			switch ConstantPoolEntryType(tag) {
			case CPTypeDynamic:
				entry.Dynamic = &ConstantDynamic{BootstrapMethodAttrIndex: bsmIdx, NameAndTypeIndex: natIdx}
			case CPTypeInvokeDynamic:
				entry.InvokeDynamic = &ConstantInvokeDynamic{BootstrapMethodAttrIndex: bsmIdx, NameAndTypeIndex: natIdx}
			}

		case CPTypeModule:
			idx, err := cr.readUint16()
			if err != nil {
				return nil, err
			}
			entry.Module = &ConstantModule{NameIndex: idx}

		case CPTypePackage:
			idx, err := cr.readUint16()
			if err != nil {
				return nil, err
			}
			entry.Package = &ConstantPackage{NameIndex: idx}

		default:
			return nil, fmt.Errorf("unknown constant pool tag: %d at index %d", tag, i)
		}

		pool[i] = entry
		i++
	}

	return pool, nil
}

func parseFieldInfos(cr *reader, count uint16, pool []ConstantPoolEntry) ([]FieldInfo, error) {
	fields := make([]FieldInfo, count)
	for i := uint16(0); i < count; i++ {
		f := FieldInfo{}
		var err error

		f.AccessFlags, err = cr.readUint16()
		if err != nil {
			return nil, err
		}
		f.NameIndex, err = cr.readUint16()
		if err != nil {
			return nil, err
		}
		f.DescriptorIndex, err = cr.readUint16()
		if err != nil {
			return nil, err
		}

		attrCount, err := cr.readUint16()
		if err != nil {
			return nil, err
		}

		f.Attributes, err = parseAttributes(cr, attrCount, pool)
		if err != nil {
			return nil, err
		}

		fields[i] = f
	}
	return fields, nil
}

func parseMethodInfos(cr *reader, count uint16, pool []ConstantPoolEntry) ([]MethodInfo, error) {
	methods := make([]MethodInfo, count)
	for i := uint16(0); i < count; i++ {
		m := MethodInfo{}
		var err error

		m.AccessFlags, err = cr.readUint16()
		if err != nil {
			return nil, err
		}
		m.NameIndex, err = cr.readUint16()
		if err != nil {
			return nil, err
		}
		m.DescriptorIndex, err = cr.readUint16()
		if err != nil {
			return nil, err
		}

		attrCount, err := cr.readUint16()
		if err != nil {
			return nil, err
		}

		m.Attributes, err = parseAttributes(cr, attrCount, pool)
		if err != nil {
			return nil, err
		}

		methods[i] = m
	}
	return methods, nil
}

func parseAttributes(cr *reader, count uint16, pool []ConstantPoolEntry) ([]AttributeInfo, error) {
	attrs := make([]AttributeInfo, count)
	for i := uint16(0); i < count; i++ {
		nameIdx, err := cr.readUint16()
		if err != nil {
			return nil, err
		}
		length, err := cr.readUint32()
		if err != nil {
			return nil, err
		}
		data, err := cr.readBytes(int(length))
		if err != nil {
			return nil, err
		}
		attrs[i] = AttributeInfo{NameIndex: nameIdx, Data: data}
	}
	return attrs, nil
}

func (cf *ClassFile) GetUTF8(idx uint16) string {
	if int(idx) < len(cf.ConstantPool) && cf.ConstantPool[idx].Tag == CPTypeUtf8 && cf.ConstantPool[idx].UTF8 != nil {
		return cf.ConstantPool[idx].UTF8.Value
	}
	return ""
}

func (cf *ClassFile) GetClassName(idx uint16) string {
	if int(idx) < len(cf.ConstantPool) && cf.ConstantPool[idx].Tag == CPTypeClass && cf.ConstantPool[idx].Class != nil {
		return cf.GetUTF8(cf.ConstantPool[idx].Class.NameIndex)
	}
	return ""
}

func (cf *ClassFile) GetMethodName(idx uint16) string {
	if int(idx) < len(cf.ConstantPool) {
		var natIdx uint16
		switch cf.ConstantPool[idx].Tag {
		case CPTypeMethodref:
			natIdx = cf.ConstantPool[idx].Methodref.NameAndTypeIndex
		case CPTypeInterfaceMethodref:
			natIdx = cf.ConstantPool[idx].InterfaceMethodref.NameAndTypeIndex
		default:
			return ""
		}
		if int(natIdx) < len(cf.ConstantPool) && cf.ConstantPool[natIdx].NameAndType != nil {
			return cf.GetUTF8(cf.ConstantPool[natIdx].NameAndType.NameIndex)
		}
	}
	return ""
}

func (cf *ClassFile) GetMethodClassName(idx uint16) string {
	if int(idx) < len(cf.ConstantPool) {
		switch cf.ConstantPool[idx].Tag {
		case CPTypeMethodref:
			return cf.GetClassName(cf.ConstantPool[idx].Methodref.ClassIndex)
		case CPTypeInterfaceMethodref:
			return cf.GetClassName(cf.ConstantPool[idx].InterfaceMethodref.ClassIndex)
		}
	}
	return ""
}

func (cf *ClassFile) GetFieldName(idx uint16) string {
	if int(idx) < len(cf.ConstantPool) && cf.ConstantPool[idx].Tag == CPTypeFieldref && cf.ConstantPool[idx].Fieldref != nil {
		natIdx := cf.ConstantPool[idx].Fieldref.NameAndTypeIndex
		if int(natIdx) < len(cf.ConstantPool) && cf.ConstantPool[natIdx].NameAndType != nil {
			return cf.GetUTF8(cf.ConstantPool[natIdx].NameAndType.NameIndex)
		}
	}
	return ""
}

func (cf *ClassFile) GetFieldClassName(idx uint16) string {
	if int(idx) < len(cf.ConstantPool) && cf.ConstantPool[idx].Tag == CPTypeFieldref && cf.ConstantPool[idx].Fieldref != nil {
		return cf.GetClassName(cf.ConstantPool[idx].Fieldref.ClassIndex)
	}
	return ""
}

func (cf *ClassFile) GetFieldIsBoolean(idx uint16) (bool, bool) {
	if int(idx) >= len(cf.ConstantPool) || cf.ConstantPool[idx].Tag != CPTypeFieldref || cf.ConstantPool[idx].Fieldref == nil {
		return false, false
	}
	fieldName := cf.GetFieldName(idx)
	for _, field := range cf.Fields {
		fName := cf.GetUTF8(field.NameIndex)
		fDesc := cf.GetUTF8(field.DescriptorIndex)
		if fName == fieldName && fDesc == "Z" {
			return true, true
		}
	}
	return false, false
}

func (cf *ClassFile) GetThisClassName() string {
	return cf.GetClassName(cf.ThisClass)
}

func (cf *ClassFile) GetSuperClassName() string {
	if cf.SuperClass == 0 {
		return ""
	}
	return cf.GetClassName(cf.SuperClass)
}

func (cf *ClassFile) GetInterfaceNames() []string {
	names := make([]string, len(cf.Interfaces))
	for i, idx := range cf.Interfaces {
		names[i] = cf.GetClassName(idx)
	}
	return names
}

func (cf *ClassFile) ParseCodeAttribute(methodIdx int) (*CodeAttribute, error) {
	if methodIdx >= len(cf.Methods) {
		return nil, fmt.Errorf("method index out of range")
	}

	m := cf.Methods[methodIdx]
	for _, attr := range m.Attributes {
		attrName := cf.GetUTF8(attr.NameIndex)
		if attrName == "Code" {
			return parseCodeAttribute(attr.Data)
		}
	}
	return nil, nil
}

func parseCodeAttribute(data []byte) (*CodeAttribute, error) {
	if len(data) < 12 {
		return nil, fmt.Errorf("code attribute too short")
	}

	code := &CodeAttribute{
		MaxStack:  binary.BigEndian.Uint16(data[0:2]),
		MaxLocals: binary.BigEndian.Uint16(data[2:4]),
	}

	codeLen := int(binary.BigEndian.Uint32(data[4:8]))
	if len(data) < 8+codeLen {
		return nil, fmt.Errorf("code length exceeds data")
	}
	code.Code = data[8 : 8+codeLen]

	offset := 8 + codeLen
	excTableLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
	offset += 2

	code.ExceptionTable = make([]ExceptionEntry, excTableLen)
	for i := 0; i < excTableLen; i++ {
		if offset+8 > len(data) {
			return nil, fmt.Errorf("exception table truncated")
		}
		code.ExceptionTable[i] = ExceptionEntry{
			StartPC:   binary.BigEndian.Uint16(data[offset : offset+2]),
			EndPC:     binary.BigEndian.Uint16(data[offset+2 : offset+4]),
			HandlerPC: binary.BigEndian.Uint16(data[offset+4 : offset+6]),
			CatchType: binary.BigEndian.Uint16(data[offset+6 : offset+8]),
		}
		offset += 8
	}

	if offset+2 <= len(data) {
		innerAttrCount := int(binary.BigEndian.Uint16(data[offset : offset+2]))
		offset += 2
		code.Attributes = make([]AttributeInfo, innerAttrCount)
		for i := 0; i < innerAttrCount; i++ {
			if offset+6 > len(data) {
				break
			}
			attrLen := int(binary.BigEndian.Uint32(data[offset+2 : offset+6]))
			code.Attributes[i] = AttributeInfo{
				NameIndex: binary.BigEndian.Uint16(data[offset : offset+2]),
				Data:      data[offset+6 : min(offset+6+attrLen, len(data))],
			}
			offset += 6 + attrLen
		}
	}

	return code, nil
}

func (cf *ClassFile) ParseLineNumberTable(methodIdx int) ([]LineNumberEntry, error) {
	code, err := cf.ParseCodeAttribute(methodIdx)
	if err != nil {
		return nil, err
	}
	if code == nil {
		return nil, nil
	}

	for _, attr := range code.Attributes {
		attrName := cf.GetUTF8(attr.NameIndex)
		if attrName == "LineNumberTable" && len(attr.Data) >= 2 {
			count := int(binary.BigEndian.Uint16(attr.Data[0:2]))
			entries := make([]LineNumberEntry, count)
			offset := 2
			for i := 0; i < count; i++ {
				if offset+4 > len(attr.Data) {
					break
				}
				entries[i] = LineNumberEntry{
					StartPC:    binary.BigEndian.Uint16(attr.Data[offset : offset+2]),
					LineNumber: binary.BigEndian.Uint16(attr.Data[offset+2 : offset+4]),
				}
				offset += 4
			}
			return entries, nil
		}
	}
	return nil, nil
}

func (cf *ClassFile) ParseLocalVariableTable(methodIdx int) ([]LocalVariableEntry, error) {
	code, err := cf.ParseCodeAttribute(methodIdx)
	if err != nil {
		return nil, err
	}
	if code == nil {
		return nil, nil
	}

	for _, attr := range code.Attributes {
		attrName := cf.GetUTF8(attr.NameIndex)
		if attrName == "LocalVariableTable" && len(attr.Data) >= 2 {
			count := int(binary.BigEndian.Uint16(attr.Data[0:2]))
			entries := make([]LocalVariableEntry, count)
			offset := 2
			for i := 0; i < count; i++ {
				if offset+10 > len(attr.Data) {
					break
				}
				entries[i] = LocalVariableEntry{
					StartPC:         binary.BigEndian.Uint16(attr.Data[offset : offset+2]),
					Length:          binary.BigEndian.Uint16(attr.Data[offset+2 : offset+4]),
					NameIndex:       binary.BigEndian.Uint16(attr.Data[offset+4 : offset+6]),
					DescriptorIndex: binary.BigEndian.Uint16(attr.Data[offset+6 : offset+8]),
					Index:           binary.BigEndian.Uint16(attr.Data[offset+8 : offset+10]),
				}
				offset += 10
			}
			return entries, nil
		}
	}
	return nil, nil
}

func decodeModifiedUTF8(data []byte) string {
	var sb strings.Builder
	for i := 0; i < len(data); {
		b := data[i]
		if b&0x80 == 0 {
			sb.WriteByte(b)
			i++
		} else if b&0xE0 == 0xC0 {
			if i+1 < len(data) {
				sb.WriteRune(rune(int(b&0x1F)<<6 | int(data[i+1]&0x3F)))
				i += 2
			} else {
				sb.WriteByte(b)
				i++
			}
		} else if b&0xF0 == 0xE0 {
			if i+2 < len(data) {
				sb.WriteRune(rune(int(b&0x0F)<<12 | int(data[i+1]&0x3F)<<6 | int(data[i+2]&0x3F)))
				i += 3
			} else {
				sb.WriteByte(b)
				i++
			}
		} else {
			sb.WriteByte(b)
			i++
		}
	}
	return sb.String()
}

type BootstrapMethodInfo struct {
	BootstrapMethodRef uint16
	Args               []uint16
}

// ResolveLambdaSAMDescriptor returns the functional interface method's
// real descriptor for a lambda/method-reference invokedynamic call site -
// e.g. "(Ljava/lang/Object;)Z" for a Predicate, giving the true number
// and types of parameters the lambda body actually takes.
//
// This is NOT the same as the invokedynamic call site's own NameAndType
// descriptor (what decompileInvokedynamic reads directly as
// "methodDesc"): that one describes how to CREATE the lambda object -
// for a non-capturing lambda, typically a zero-argument descriptor like
// "()Ljava/util/function/Predicate;", since building the lambda instance
// itself takes no arguments even though the Predicate it produces takes
// one. The real parameter count/types live in the bootstrap method's
// OWN first static argument (samMethodType, JVMS 4.7.23 - the same
// LambdaMetafactory.metafactory bootstrap call that ResolveLambdaTarget
// already reads bsm.Args[1] - implMethod - from; this reads bsm.Args[0]
// instead). Using the call-site descriptor's arity where this is needed
// silently drops the lambda's own parameters whenever the lambda takes
// any (i.e. essentially always, since a zero-parameter functional
// interface is rare) - confirmed as a real bug via decompilation of
// real open-source code (a Predicate<PlayerEntity> lambda's own
// parameter "p" was dropped entirely, producing invalid Java with p
// referenced but never declared).
func (cf *ClassFile) ResolveLambdaSAMDescriptor(invDynIdx uint16) (string, bool) {
	if int(invDynIdx) >= len(cf.ConstantPool) {
		return "", false
	}
	entry := cf.ConstantPool[invDynIdx]
	if entry.InvokeDynamic == nil {
		return "", false
	}
	bsmIndex := int(entry.InvokeDynamic.BootstrapMethodAttrIndex)

	bsmAttr := cf.findBootstrapMethodsAttr()
	if bsmAttr == nil {
		return "", false
	}
	methods, _ := cf.parseBootstrapMethods(bsmAttr.Data)
	if bsmIndex >= len(methods) {
		return "", false
	}
	bsm := methods[bsmIndex]

	if int(bsm.BootstrapMethodRef) >= len(cf.ConstantPool) {
		return "", false
	}
	bsmEntry := cf.ConstantPool[bsm.BootstrapMethodRef]
	if bsmEntry.MethodHandle == nil {
		return "", false
	}
	bsmRefIdx := bsmEntry.MethodHandle.ReferenceIndex
	if int(bsmRefIdx) >= len(cf.ConstantPool) {
		return "", false
	}
	bsmRefEntry := cf.ConstantPool[bsmRefIdx]
	if bsmRefEntry.Methodref == nil {
		return "", false
	}
	bsmClassName := cf.GetClassName(bsmRefEntry.Methodref.ClassIndex)
	bsmMethodName := ""
	if bsmRefEntry.Methodref.NameAndTypeIndex > 0 {
		natEntry := cf.ConstantPool[bsmRefEntry.Methodref.NameAndTypeIndex]
		if natEntry.NameAndType != nil {
			bsmMethodName = cf.GetUTF8(natEntry.NameAndType.NameIndex)
		}
	}
	if bsmClassName != "java/lang/invoke/LambdaMetafactory" || bsmMethodName != "metafactory" {
		return "", false
	}

	if len(bsm.Args) < 1 {
		return "", false
	}
	samMethodTypeIdx := bsm.Args[0]
	if int(samMethodTypeIdx) >= len(cf.ConstantPool) {
		return "", false
	}
	samEntry := cf.ConstantPool[samMethodTypeIdx]
	if samEntry.MethodType == nil {
		return "", false
	}
	return cf.GetUTF8(samEntry.MethodType.DescriptorIndex), true
}

func (cf *ClassFile) ResolveLambdaTarget(invDynIdx uint16) (className string, methodName string, ok bool) {
	if int(invDynIdx) >= len(cf.ConstantPool) {
		return "", "", false
	}
	entry := cf.ConstantPool[invDynIdx]
	if entry.InvokeDynamic == nil {
		return "", "", false
	}
	bsmIndex := int(entry.InvokeDynamic.BootstrapMethodAttrIndex)

	bsmAttr := cf.findBootstrapMethodsAttr()
	if bsmAttr == nil {
		return "", "", false
	}

	methods, _ := cf.parseBootstrapMethods(bsmAttr.Data)
	if bsmIndex >= len(methods) {
		return "", "", false
	}
	bsm := methods[bsmIndex]

	if int(bsm.BootstrapMethodRef) >= len(cf.ConstantPool) {
		return "", "", false
	}
	bsmEntry := cf.ConstantPool[bsm.BootstrapMethodRef]
	if bsmEntry.MethodHandle == nil {
		return "", "", false
	}
	bsmRefIdx := bsmEntry.MethodHandle.ReferenceIndex
	if int(bsmRefIdx) >= len(cf.ConstantPool) {
		return "", "", false
	}
	bsmRefEntry := cf.ConstantPool[bsmRefIdx]
	if bsmRefEntry.Methodref == nil {
		return "", "", false
	}
	bsmClassName := cf.GetClassName(bsmRefEntry.Methodref.ClassIndex)
	bsmMethodName := ""
	if bsmRefEntry.Methodref.NameAndTypeIndex > 0 {
		natEntry := cf.ConstantPool[bsmRefEntry.Methodref.NameAndTypeIndex]
		if natEntry.NameAndType != nil {
			bsmMethodName = cf.GetUTF8(natEntry.NameAndType.NameIndex)
		}
	}
	if bsmClassName != "java/lang/invoke/LambdaMetafactory" || bsmMethodName != "metafactory" {
		return "", "", false
	}

	if len(bsm.Args) < 2 {
		return "", "", false
	}
	targetHandleIdx := bsm.Args[1]
	if int(targetHandleIdx) >= len(cf.ConstantPool) {
		return "", "", false
	}
	targetHandle := cf.ConstantPool[targetHandleIdx]
	if targetHandle.MethodHandle == nil {
		return "", "", false
	}
	targetRefIdx := targetHandle.MethodHandle.ReferenceIndex
	if int(targetRefIdx) >= len(cf.ConstantPool) {
		return "", "", false
	}
	targetRef := cf.ConstantPool[targetRefIdx]
	if targetRef.Methodref == nil {
		return "", "", false
	}
	className = cf.GetClassName(targetRef.Methodref.ClassIndex)
	if targetRef.Methodref.NameAndTypeIndex > 0 {
		natEntry := cf.ConstantPool[targetRef.Methodref.NameAndTypeIndex]
		if natEntry.NameAndType != nil {
			methodName = cf.GetUTF8(natEntry.NameAndType.NameIndex)
		}
	}
	return className, methodName, true
}

func (cf *ClassFile) findBootstrapMethodsAttr() *AttributeInfo {
	for _, attr := range cf.Attributes {
		attrName := cf.GetUTF8(attr.NameIndex)
		if attrName == "BootstrapMethods" {
			return &attr
		}
	}
	return nil
}

func (cf *ClassFile) parseBootstrapMethods(data []byte) ([]BootstrapMethodInfo, error) {
	if len(data) < 2 {
		return nil, fmt.Errorf("too short")
	}
	numMethods := int(data[0])<<8 | int(data[1])
	off := 2
	var methods []BootstrapMethodInfo
	for i := 0; i < numMethods; i++ {
		if off+4 > len(data) {
			break
		}
		bsmRef := uint16(data[off])<<8 | uint16(data[off+1])
		off += 2
		numArgs := int(data[off])<<8 | int(data[off+1])
		off += 2
		var args []uint16
		for j := 0; j < numArgs; j++ {
			if off+2 > len(data) {
				break
			}
			args = append(args, uint16(data[off])<<8|uint16(data[off+1]))
			off += 2
		}
		methods = append(methods, BootstrapMethodInfo{BootstrapMethodRef: bsmRef, Args: args})
	}
	return methods, nil
}
