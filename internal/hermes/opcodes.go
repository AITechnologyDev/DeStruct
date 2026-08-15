package hermes

import "encoding/binary"

type OperandType struct {
	Name   string
	Size   int
	IsAddr bool
	IsSigned bool
}

var (
	Reg8    = OperandType{"Reg8", 1, false, false}
	Reg32   = OperandType{"Reg32", 4, false, false}
	UInt8   = OperandType{"UInt8", 1, false, false}
	UInt16  = OperandType{"UInt16", 2, false, false}
	UInt32  = OperandType{"UInt32", 4, false, false}
	Addr8   = OperandType{"Addr8", 1, true, true}
	Addr32  = OperandType{"Addr32", 4, true, true}
	Imm32   = OperandType{"Imm32", 4, false, true}
	DoubleT = OperandType{"Double", 8, false, false}
)

type OperandMeaning int

const (
	MeaningNone       OperandMeaning = 0
	MeaningStringID   OperandMeaning = 1
	MeaningFunctionID OperandMeaning = 2
	MeaningBigIntID   OperandMeaning = 3
)

type InstructionDef struct {
	Name     string
	Opcode   int
	Operands []OperandType
	Meanings []OperandMeaning
	HasRet   bool
	BinSize  int
}

func (d *InstructionDef) Size() int {
	return 1 + d.BinSize
}

func NewInst(name string, opcode int, operands []OperandType, meanings []OperandMeaning, hasRet bool) *InstructionDef {
	binSize := 0
	for _, o := range operands {
		binSize += o.Size
	}
	return &InstructionDef{
		Name:     name,
		Opcode:   opcode,
		Operands: operands,
		Meanings: meanings,
		HasRet:   hasRet,
		BinSize:  binSize,
	}
}

type ParsedInstruction struct {
	Inst       *InstructionDef
	Offset     uint32
	Args       []uint64
	JumpTable  []uint32
	NextOffset uint32
}

func (pi *ParsedInstruction) Format(file *HBCFile) string {
	s := pi.Inst.Name
	if len(pi.Args) == 0 {
		return s
	}
	for i, arg := range pi.Args {
		if i < len(pi.Inst.Meanings) && pi.Inst.Meanings[i] == MeaningStringID && int(arg) < len(file.Strings) {
			s += " " + file.Strings[arg]
		} else if i < len(pi.Inst.Operands) && pi.Inst.Operands[i].IsAddr {
			target := pi.Offset + uint32(int32(arg))
			s += " " + formatAddr(target)
		} else {
			s += " " + formatArg(arg)
		}
	}
	return s
}

func formatAddr(a uint32) string {
	return "0x" + hex32(a)
}

func formatArg(a uint64) string {
	if a <= 0xFFFFFFFF {
		return "0x" + hex32(uint32(a))
	}
	return "0x" + hex64(a)
}

func hex32(v uint32) string {
	const hex = "0123456789abcdef"
	var b [8]byte
	for i := 7; i >= 0; i-- {
		b[i] = hex[v&0xf]
		v >>= 4
	}
	return string(b[:])
}

func hex64(v uint64) string {
	const hex = "0123456789abcdef"
	var b [16]byte
	for i := 15; i >= 0; i-- {
		b[i] = hex[v&0xf]
		v >>= 4
	}
	return string(b[:])
}

func decodeInstruction(data []byte, offset uint32, opcodeTable map[byte]*InstructionDef) *ParsedInstruction {
	if len(data) == 0 {
		return nil
	}
	opcode := data[0]
	inst, ok := opcodeTable[opcode]
	if !ok {
		return &ParsedInstruction{
			Inst:       &InstructionDef{Name: "Unknown", Opcode: int(opcode)},
			Offset:     offset,
			Args:       []uint64{uint64(opcode)},
			NextOffset: offset + 1,
		}
	}

	pi := &ParsedInstruction{
		Inst:   inst,
		Offset: offset,
		Args:   make([]uint64, len(inst.Operands)),
	}

	pos := 1
	for i, op := range inst.Operands {
		if pos+op.Size > len(data) {
			pi.Args[i] = 0
			continue
		}
		switch op.Size {
		case 1:
			if op.IsSigned {
				pi.Args[i] = uint64(int8(data[pos]))
			} else {
				pi.Args[i] = uint64(data[pos])
			}
		case 2:
			v := binary.LittleEndian.Uint16(data[pos:])
			if op.IsSigned {
				pi.Args[i] = uint64(int16(v))
			} else {
				pi.Args[i] = uint64(v)
			}
		case 4:
			v := binary.LittleEndian.Uint32(data[pos:])
			if op.IsSigned {
				pi.Args[i] = uint64(int32(v))
			} else {
				pi.Args[i] = uint64(v)
			}
		case 8:
			pi.Args[i] = binary.LittleEndian.Uint64(data[pos:])
		}
		pos += op.Size
	}

	pi.NextOffset = offset + uint32(inst.Size())
	return pi
}

var builtinNames = []string{
	"Array.isArray", "Date.UTC", "Date.parse", "JSON.parse", "JSON.stringify",
	"Math.abs", "Math.acos", "Math.asin", "Math.atan", "Math.atan2",
	"Math.ceil", "Math.cos", "Math.exp", "Math.floor", "Math.hypot",
	"Math.imul", "Math.log", "Math.max", "Math.min", "Math.pow",
	"Math.round", "Math.sin", "Math.sqrt", "Math.tan", "Math.trunc",
	"Object.create", "Object.defineProperties", "Object.defineProperty",
	"Object.freeze", "Object.getOwnPropertyDescriptor", "Object.getOwnPropertyNames",
	"Object.getPrototypeOf", "Object.isExtensible", "Object.isFrozen",
	"Object.keys", "Object.seal", "String.fromCharCode", "silentSetPrototypeOf",
	"requireFast", "getTemplateObject", "ensureObject", "getMethod",
	"throwTypeError", "throwReferenceError", "copyDataProperties", "copyRestArgs",
	"arraySpread", "apply", "applyArguments", "applyWithNewTarget",
	"exportAll", "exponentiationOperator", "initRegexNamedGroups",
	"functionPrototypeApply", "functionPrototypeCall",
	"spawnAsync", "makeAsyncIterator", "awaitAsyncGenerator",
}

// buildOpcodeTableForVersion returns the opcode table matching the given
// Hermes bytecode format version. Hermes renumbers/adds/removes opcodes
// between format versions (v98 and v99 alone differ in the position of 75
// out of ~220 opcodes), so using the wrong table for a file's actual
// version produces systematically wrong instruction names and operand
// sizes - not a cosmetic issue, since a wrong operand size misaligns
// every instruction that follows it in the stream.
//
// Dedicated, source-verified tables exist for versions 97, 98, and 99
// (the versions real-world Hermes/React Native bundles are built with as
// of this writing). For any other version, this falls back to the
// nearest of those three rather than refusing outright: bytecode formats
// evolve incrementally, so a neighboring version's table is far more
// likely to be correct (or only slightly off) than not having any
// version-appropriate table at all. Callers that care whether a file's
// version has a dedicated table should check f.Header.Version themselves
// against 97/98/99.
func buildOpcodeTableForVersion(version uint32) map[byte]*InstructionDef {
	switch {
	case version == 97:
		return buildOpcodeTable97()
	case version == 98:
		return buildOpcodeTable98()
	case version == 99:
		return buildOpcodeTable99()
	case version < 97:
		return buildOpcodeTable97()
	default: // version > 99
		return buildOpcodeTable99()
	}
}

func buildOpcodeTable99() map[byte]*InstructionDef {
	t := make(map[byte]*InstructionDef)

	def := func(name string, opcode int, operands []OperandType, meanings []OperandMeaning, hasRet bool) {
		t[byte(opcode)] = NewInst(name, opcode, operands, meanings, hasRet)
	}

	noMeaning := func(n int) []OperandMeaning {
		m := make([]OperandMeaning, n)
		for i := range m {
			m[i] = MeaningNone
		}
		return m
	}

	// Object/Array creation
	def("Unreachable", 0, nil, nil, false)
	def("NewObjectWithBuffer", 1, []OperandType{Reg8, UInt16, UInt16}, noMeaning(3), false)
	def("NewObjectWithBufferLong", 2, []OperandType{Reg8, UInt32, UInt32}, noMeaning(3), false)
	def("NewObjectWithBufferAndParent", 3, []OperandType{Reg8, Reg8, UInt32, UInt32}, noMeaning(4), false)
	def("NewTypedObjectWithBuffer", 4, []OperandType{Reg8, Reg8, UInt32, UInt32, UInt8}, noMeaning(5), false)
	def("NewObject", 5, []OperandType{Reg8}, noMeaning(1), false)
	def("NewObjectWithParent", 6, []OperandType{Reg8, Reg8}, noMeaning(2), false)
	def("NewArrayWithBuffer", 7, []OperandType{Reg8, UInt16, UInt16, UInt16}, noMeaning(4), false)
	def("NewArrayWithBufferLong", 8, []OperandType{Reg8, UInt16, UInt16, UInt32}, noMeaning(4), false)
	def("NewArray", 9, []OperandType{Reg8, UInt16}, noMeaning(2), false)
	def("NewFastArray", 10, []OperandType{Reg8, UInt16}, noMeaning(2), false)

	// Fast array ops
	def("FastArrayLength", 11, []OperandType{Reg8, Reg8}, noMeaning(2), false)
	def("FastArrayLoad", 12, []OperandType{Reg8, Reg8, Reg8}, noMeaning(3), false)
	def("FastArrayStore", 13, []OperandType{Reg8, Reg8, Reg8}, noMeaning(3), false)
	def("FastArrayPush", 14, []OperandType{Reg8, Reg8}, noMeaning(2), false)
	def("FastArrayAppend", 15, []OperandType{Reg8, Reg8}, noMeaning(2), false)

	// Move
	def("Mov", 16, []OperandType{Reg8, Reg8}, noMeaning(2), false)
	def("MovLong", 17, []OperandType{Reg32, Reg32}, noMeaning(2), false)

	// Unary
	def("Negate", 18, []OperandType{Reg8, Reg8}, noMeaning(2), false)
	def("Not", 19, []OperandType{Reg8, Reg8}, noMeaning(2), false)
	def("BitNot", 20, []OperandType{Reg8, Reg8}, noMeaning(2), false)
	def("TypeOf", 21, []OperandType{Reg8, Reg8}, noMeaning(2), false)

	// Comparison
	def("Eq", 22, []OperandType{Reg8, Reg8, Reg8}, noMeaning(3), false)
	def("StrictEq", 23, []OperandType{Reg8, Reg8, Reg8}, noMeaning(3), false)
	def("Neq", 24, []OperandType{Reg8, Reg8, Reg8}, noMeaning(3), false)
	def("StrictNeq", 25, []OperandType{Reg8, Reg8, Reg8}, noMeaning(3), false)
	def("Less", 26, []OperandType{Reg8, Reg8, Reg8}, noMeaning(3), false)
	def("LessEq", 27, []OperandType{Reg8, Reg8, Reg8}, noMeaning(3), false)
	def("Greater", 28, []OperandType{Reg8, Reg8, Reg8}, noMeaning(3), false)
	def("GreaterEq", 29, []OperandType{Reg8, Reg8, Reg8}, noMeaning(3), false)

	// Arithmetic
	def("Add", 30, []OperandType{Reg8, Reg8, Reg8}, noMeaning(3), false)
	def("AddN", 31, []OperandType{Reg8, Reg8, Reg8}, noMeaning(3), false)
	def("AddS", 32, []OperandType{Reg8, Reg8, Reg8}, noMeaning(3), false)
	def("Mul", 33, []OperandType{Reg8, Reg8, Reg8}, noMeaning(3), false)
	def("MulN", 34, []OperandType{Reg8, Reg8, Reg8}, noMeaning(3), false)
	def("Div", 35, []OperandType{Reg8, Reg8, Reg8}, noMeaning(3), false)
	def("DivN", 36, []OperandType{Reg8, Reg8, Reg8}, noMeaning(3), false)
	def("Mod", 37, []OperandType{Reg8, Reg8, Reg8}, noMeaning(3), false)
	def("Sub", 38, []OperandType{Reg8, Reg8, Reg8}, noMeaning(3), false)
	def("SubN", 39, []OperandType{Reg8, Reg8, Reg8}, noMeaning(3), false)

	// Bitwise
	def("LShift", 40, []OperandType{Reg8, Reg8, Reg8}, noMeaning(3), false)
	def("RShift", 41, []OperandType{Reg8, Reg8, Reg8}, noMeaning(3), false)
	def("URshift", 42, []OperandType{Reg8, Reg8, Reg8}, noMeaning(3), false)
	def("BitAnd", 43, []OperandType{Reg8, Reg8, Reg8}, noMeaning(3), false)
	def("BitXor", 44, []OperandType{Reg8, Reg8, Reg8}, noMeaning(3), false)
	def("BitOr", 45, []OperandType{Reg8, Reg8, Reg8}, noMeaning(3), false)

	// Inc/Dec
	def("Inc", 46, []OperandType{Reg8, Reg8}, noMeaning(2), false)
	def("Dec", 47, []OperandType{Reg8, Reg8}, noMeaning(2), false)

	// Type checks
	def("InstanceOf", 48, []OperandType{Reg8, Reg8, Reg8}, noMeaning(3), false)
	def("IsIn", 49, []OperandType{Reg8, Reg8, Reg8}, noMeaning(3), false)
	def("PrivateIsIn", 50, []OperandType{Reg8, Reg8, Reg8, Reg8}, noMeaning(4), false)
	def("TypeOfIs", 51, []OperandType{Reg8, Reg8, UInt16}, noMeaning(3), false)

	// Environment
	def("GetParentEnvironment", 52, []OperandType{Reg8, UInt8}, noMeaning(2), false)
	def("GetEnvironment", 53, []OperandType{Reg8, Reg8, UInt8}, noMeaning(3), false)
	def("GetClosureEnvironment", 54, []OperandType{Reg8, Reg8}, noMeaning(2), false)
	def("StoreToEnvironment", 55, []OperandType{Reg8, UInt8, Reg8}, noMeaning(3), false)
	def("StoreToEnvironmentL", 56, []OperandType{Reg8, UInt16, Reg8}, noMeaning(3), false)
	def("StoreNPToEnvironment", 57, []OperandType{Reg8, UInt8, Reg8}, noMeaning(3), false)
	def("StoreNPToEnvironmentL", 58, []OperandType{Reg8, UInt16, Reg8}, noMeaning(3), false)
	def("LoadFromEnvironment", 59, []OperandType{Reg8, Reg8, UInt8}, noMeaning(3), false)
	def("LoadFromEnvironmentL", 60, []OperandType{Reg8, Reg8, UInt16}, noMeaning(3), false)

	def("GetGlobalObject", 61, []OperandType{Reg8}, noMeaning(1), false)
	def("GetNewTarget", 62, []OperandType{Reg8}, noMeaning(1), false)
	def("LoadParentNoTraps", 63, []OperandType{Reg8, Reg8}, noMeaning(2), false)
	def("CreateFunctionEnvironment", 64, []OperandType{Reg8, UInt8}, noMeaning(2), false)
	def("CreateTopLevelEnvironment", 65, []OperandType{Reg8, UInt32}, noMeaning(2), false)
	def("CreateEnvironment", 66, []OperandType{Reg8, Reg8, UInt32}, noMeaning(3), false)
	def("DeclareGlobalVar", 67, []OperandType{UInt32}, []OperandMeaning{MeaningStringID}, false)

	// Property access
	def("GetByIdShort", 68, []OperandType{Reg8, Reg8, UInt8, UInt8}, []OperandMeaning{MeaningNone, MeaningNone, MeaningNone, MeaningStringID}, false)
	def("GetById", 69, []OperandType{Reg8, Reg8, UInt8, UInt16}, []OperandMeaning{MeaningNone, MeaningNone, MeaningNone, MeaningStringID}, false)
	def("GetByIdLong", 70, []OperandType{Reg8, Reg8, UInt8, UInt32}, []OperandMeaning{MeaningNone, MeaningNone, MeaningNone, MeaningStringID}, false)
	def("GetByIdWithReceiverLong", 71, []OperandType{Reg8, Reg8, UInt8, Reg8, UInt32}, []OperandMeaning{MeaningNone, MeaningNone, MeaningNone, MeaningNone, MeaningStringID}, false)

	def("TryGetById", 72, []OperandType{Reg8, Reg8, UInt8, UInt16}, []OperandMeaning{MeaningNone, MeaningNone, MeaningNone, MeaningStringID}, false)
	def("TryGetByIdLong", 73, []OperandType{Reg8, Reg8, UInt8, UInt32}, []OperandMeaning{MeaningNone, MeaningNone, MeaningNone, MeaningStringID}, false)

	def("PutByIdLoose", 74, []OperandType{Reg8, Reg8, UInt8, UInt16}, []OperandMeaning{MeaningNone, MeaningNone, MeaningNone, MeaningStringID}, false)
	def("PutByIdStrict", 75, []OperandType{Reg8, Reg8, UInt8, UInt16}, []OperandMeaning{MeaningNone, MeaningNone, MeaningNone, MeaningStringID}, false)
	def("PutByIdLooseLong", 76, []OperandType{Reg8, Reg8, UInt8, UInt32}, []OperandMeaning{MeaningNone, MeaningNone, MeaningNone, MeaningStringID}, false)
	def("PutByIdStrictLong", 77, []OperandType{Reg8, Reg8, UInt8, UInt32}, []OperandMeaning{MeaningNone, MeaningNone, MeaningNone, MeaningStringID}, false)

	def("TryPutByIdLoose", 78, []OperandType{Reg8, Reg8, UInt8, UInt16}, []OperandMeaning{MeaningNone, MeaningNone, MeaningNone, MeaningStringID}, false)
	def("TryPutByIdStrict", 79, []OperandType{Reg8, Reg8, UInt8, UInt16}, []OperandMeaning{MeaningNone, MeaningNone, MeaningNone, MeaningStringID}, false)
	def("TryPutByIdLooseLong", 80, []OperandType{Reg8, Reg8, UInt8, UInt32}, []OperandMeaning{MeaningNone, MeaningNone, MeaningNone, MeaningStringID}, false)
	def("TryPutByIdStrictLong", 81, []OperandType{Reg8, Reg8, UInt8, UInt32}, []OperandMeaning{MeaningNone, MeaningNone, MeaningNone, MeaningStringID}, false)

	def("PutOwnBySlotIdx", 82, []OperandType{Reg8, Reg8, UInt8}, noMeaning(3), false)
	def("PutOwnBySlotIdxLong", 83, []OperandType{Reg8, Reg8, UInt32}, noMeaning(3), false)
	def("GetOwnBySlotIdx", 84, []OperandType{Reg8, Reg8, UInt8}, noMeaning(3), false)
	def("GetOwnBySlotIdxLong", 85, []OperandType{Reg8, Reg8, UInt32}, noMeaning(3), false)

	def("DefineOwnById", 86, []OperandType{Reg8, Reg8, UInt8, UInt16}, noMeaning(4), false)
	def("DefineOwnByIdLong", 87, []OperandType{Reg8, Reg8, UInt8, UInt32}, []OperandMeaning{MeaningNone, MeaningNone, MeaningNone, MeaningStringID}, false)
	def("DefineOwnByIndex", 88, []OperandType{Reg8, Reg8, UInt8}, noMeaning(3), false)
	def("DefineOwnByIndexL", 89, []OperandType{Reg8, Reg8, UInt32}, noMeaning(3), false)

	def("DefineOwnInDenseArray", 90, []OperandType{Reg8, Reg8, UInt8}, noMeaning(3), false)
	def("DefineOwnInDenseArrayL", 91, []OperandType{Reg8, Reg8, UInt16}, noMeaning(3), false)
	def("DefineOwnByVal", 92, []OperandType{Reg8, Reg8, Reg8, UInt8}, noMeaning(4), false)

	def("GetByVal", 93, []OperandType{Reg8, Reg8, Reg8}, noMeaning(3), false)
	def("GetByIndex", 94, []OperandType{Reg8, Reg8, UInt8}, noMeaning(3), false)
	def("GetByValWithReceiver", 95, []OperandType{Reg8, Reg8, Reg8, Reg8}, noMeaning(4), false)

	def("PutByValLoose", 96, []OperandType{Reg8, Reg8, Reg8}, noMeaning(3), false)
	def("PutByValStrict", 97, []OperandType{Reg8, Reg8, Reg8}, noMeaning(3), false)
	def("PutByValWithReceiver", 98, []OperandType{Reg8, Reg8, Reg8, Reg8, UInt8}, noMeaning(5), false)
	def("DelByVal", 99, []OperandType{Reg8, Reg8, Reg8, UInt8}, noMeaning(4), false)

	def("AddOwnPrivateBySym", 100, []OperandType{Reg8, Reg8, Reg8}, noMeaning(3), false)
	def("GetOwnPrivateBySym", 101, []OperandType{Reg8, Reg8, UInt8, Reg8}, noMeaning(4), false)
	def("PutOwnPrivateBySym", 102, []OperandType{Reg8, Reg8, UInt8, Reg8}, noMeaning(4), false)

	def("DefineOwnGetterSetterByVal", 103, []OperandType{Reg8, Reg8, Reg8, Reg8, UInt8}, noMeaning(5), false)
	def("GetPNameList", 104, []OperandType{Reg8, Reg8, Reg8, Reg8}, noMeaning(4), false)
	def("GetNextPName", 105, []OperandType{Reg8, Reg8, Reg8, Reg8, Reg8}, noMeaning(5), false)

	// Calls
	def("Call", 106, []OperandType{Reg8, Reg8, UInt8}, noMeaning(3), true)
	def("Construct", 107, []OperandType{Reg8, Reg8, UInt8}, noMeaning(3), true)
	def("Call1", 108, []OperandType{Reg8, Reg8, Reg8}, noMeaning(3), true)
	def("CallWithNewTarget", 109, []OperandType{Reg8, Reg8, Reg8, UInt8}, noMeaning(4), true)
	def("Call2", 110, []OperandType{Reg8, Reg8, Reg8, Reg8}, noMeaning(4), true)
	def("Call3", 111, []OperandType{Reg8, Reg8, Reg8, Reg8, Reg8}, noMeaning(5), true)
	def("Call4", 112, []OperandType{Reg8, Reg8, Reg8, Reg8, Reg8, Reg8}, noMeaning(6), true)
	def("CallWithNewTargetLong", 113, []OperandType{Reg8, Reg8, Reg8, Reg8}, noMeaning(4), true)
	def("CallRequire", 114, []OperandType{Reg8, Reg8, UInt32}, noMeaning(3), true)

	def("CallBuiltin", 115, []OperandType{Reg8, UInt8, UInt8}, noMeaning(3), false)
	def("CallBuiltinLong", 116, []OperandType{Reg8, UInt8, UInt32}, noMeaning(3), false)
	def("GetBuiltinClosure", 117, []OperandType{Reg8, UInt8}, noMeaning(2), false)

	def("Ret", 118, []OperandType{Reg8}, noMeaning(1), false)
	def("Catch", 119, []OperandType{Reg8}, noMeaning(1), false)
	def("DirectEval", 120, []OperandType{Reg8, Reg8, UInt8}, noMeaning(3), false)
	def("Throw", 121, []OperandType{Reg8}, noMeaning(1), false)
	def("ThrowIfEmpty", 122, []OperandType{Reg8, Reg8}, noMeaning(2), false)
	def("ThrowIfUndefined", 123, []OperandType{Reg8, Reg8}, noMeaning(2), false)
	def("ThrowIfThisInitialized", 124, []OperandType{Reg8}, noMeaning(1), false)
	def("Debugger", 125, nil, nil, false)
	def("AsyncBreakCheck", 126, nil, nil, false)
	def("ProfilePoint", 127, []OperandType{UInt16}, noMeaning(1), false)

	// Class creation
	def("CreateBaseClass", 128, []OperandType{Reg8, Reg8, Reg8, UInt16}, noMeaning(4), false)
	def("CreateBaseClassLongIndex", 129, []OperandType{Reg8, Reg8, Reg8, UInt32}, noMeaning(4), false)
	def("CreateDerivedClass", 130, []OperandType{Reg8, Reg8, Reg8, Reg8, UInt16}, noMeaning(5), false)
	def("CreateDerivedClassLongIndex", 131, []OperandType{Reg8, Reg8, Reg8, Reg8, UInt32}, noMeaning(5), false)

	// Closures
	def("CreateClosure", 132, []OperandType{Reg8, Reg8, UInt16}, []OperandMeaning{MeaningNone, MeaningNone, MeaningFunctionID}, false)
	def("CreateClosureLongIndex", 133, []OperandType{Reg8, Reg8, UInt32}, []OperandMeaning{MeaningNone, MeaningNone, MeaningFunctionID}, false)
	def("CreateThisForNew", 134, []OperandType{Reg8, Reg8, UInt8}, noMeaning(3), false)
	def("CreateThisForSuper", 135, []OperandType{Reg8, Reg8, Reg8, UInt8}, noMeaning(4), false)
	def("SelectObject", 136, []OperandType{Reg8, Reg8, Reg8}, noMeaning(3), false)

	// Parameters
	def("LoadParam", 137, []OperandType{Reg8, UInt8}, noMeaning(2), false)
	def("LoadParamLong", 138, []OperandType{Reg8, UInt32}, noMeaning(2), false)

	// Constants
	def("LoadConstUInt8", 139, []OperandType{Reg8, UInt8}, noMeaning(2), false)
	def("LoadConstInt", 140, []OperandType{Reg8, Imm32}, noMeaning(2), false)
	def("LoadConstDouble", 141, []OperandType{Reg8, DoubleT}, noMeaning(2), false)
	def("LoadConstBigInt", 142, []OperandType{Reg8, UInt16}, []OperandMeaning{MeaningNone, MeaningBigIntID}, false)
	def("LoadConstBigIntLongIndex", 143, []OperandType{Reg8, UInt32}, []OperandMeaning{MeaningNone, MeaningBigIntID}, false)
	def("LoadConstString", 144, []OperandType{Reg8, UInt16}, []OperandMeaning{MeaningNone, MeaningStringID}, false)
	def("LoadConstStringLongIndex", 145, []OperandType{Reg8, UInt32}, []OperandMeaning{MeaningNone, MeaningStringID}, false)
	def("LoadConstEmpty", 146, []OperandType{Reg8}, noMeaning(1), false)
	def("LoadConstUndefined", 147, []OperandType{Reg8}, noMeaning(1), false)
	def("LoadConstNull", 148, []OperandType{Reg8}, noMeaning(1), false)
	def("LoadConstTrue", 149, []OperandType{Reg8}, noMeaning(1), false)
	def("LoadConstFalse", 150, []OperandType{Reg8}, noMeaning(1), false)
	def("LoadConstZero", 151, []OperandType{Reg8}, noMeaning(1), false)

	def("CoerceThisNS", 152, []OperandType{Reg8, Reg8}, noMeaning(2), false)
	def("LoadThisNS", 153, []OperandType{Reg8}, noMeaning(1), false)
	def("ToNumber", 154, []OperandType{Reg8, Reg8}, noMeaning(2), false)
	def("ToNumeric", 155, []OperandType{Reg8, Reg8}, noMeaning(2), false)
	def("ToInt32", 156, []OperandType{Reg8, Reg8}, noMeaning(2), false)
	def("ToUint32", 157, []OperandType{Reg8, Reg8}, noMeaning(2), false)
	def("AddEmptyString", 158, []OperandType{Reg8, Reg8}, noMeaning(2), false)
	def("CreatePrivateName", 159, []OperandType{Reg8, UInt32}, []OperandMeaning{MeaningNone, MeaningStringID}, false)

	def("GetArgumentsPropByValLoose", 160, []OperandType{Reg8, Reg8, Reg8}, noMeaning(3), false)
	def("GetArgumentsPropByValStrict", 161, []OperandType{Reg8, Reg8, Reg8}, noMeaning(3), false)
	def("GetArgumentsLength", 162, []OperandType{Reg8, Reg8}, noMeaning(2), false)
	def("ReifyArgumentsStrict", 163, []OperandType{Reg8}, noMeaning(1), false)
	def("ReifyArgumentsLoose", 164, []OperandType{Reg8}, noMeaning(1), false)
	def("ToPropertyKey", 165, []OperandType{Reg8, Reg8}, noMeaning(2), false)
	def("CreateRegExp", 166, []OperandType{Reg8, UInt32, UInt32, UInt32}, []OperandMeaning{MeaningNone, MeaningStringID, MeaningStringID, MeaningNone}, false)

	// Switch
	def("UIntSwitchImm", 167, []OperandType{Reg8, UInt32, Addr32, UInt32, UInt32}, noMeaning(5), false)
	def("StringSwitchImm", 168, []OperandType{Reg8, UInt32, UInt32, Addr32, UInt32}, noMeaning(5), false)

	// Generators
	def("CreateGenerator", 169, []OperandType{Reg8, Reg8, UInt16}, []OperandMeaning{MeaningNone, MeaningNone, MeaningFunctionID}, false)
	def("CreateGeneratorLongIndex", 170, []OperandType{Reg8, Reg8, UInt32}, []OperandMeaning{MeaningNone, MeaningNone, MeaningFunctionID}, false)

	// Iterators
	def("IteratorBegin", 171, []OperandType{Reg8, Reg8}, noMeaning(2), false)
	def("IteratorNext", 172, []OperandType{Reg8, Reg8, Reg8}, noMeaning(3), false)
	def("IteratorClose", 173, []OperandType{Reg8, UInt8}, noMeaning(2), false)
	def("TypedLoadParent", 174, []OperandType{Reg8, Reg8}, noMeaning(2), false)

	// Jumps
	def("Jmp", 175, []OperandType{Addr8}, noMeaning(1), false)
	def("JmpLong", 176, []OperandType{Addr32}, noMeaning(1), false)
	def("JmpTrue", 177, []OperandType{Addr8, Reg8}, noMeaning(2), false)
	def("JmpTrueLong", 178, []OperandType{Addr32, Reg8}, noMeaning(2), false)
	def("JmpFalse", 179, []OperandType{Addr8, Reg8}, noMeaning(2), false)
	def("JmpFalseLong", 180, []OperandType{Addr32, Reg8}, noMeaning(2), false)
	def("JmpUndefined", 181, []OperandType{Addr8, Reg8}, noMeaning(2), false)
	def("JmpUndefinedLong", 182, []OperandType{Addr32, Reg8}, noMeaning(2), false)
	def("JmpTypeOfIs", 183, []OperandType{Addr32, Reg8, UInt16}, noMeaning(3), false)

	def("JLess", 184, []OperandType{Addr8, Reg8, Reg8}, noMeaning(3), false)
	def("JLessLong", 185, []OperandType{Addr32, Reg8, Reg8}, noMeaning(3), false)
	def("JNotLess", 186, []OperandType{Addr8, Reg8, Reg8}, noMeaning(3), false)
	def("JNotLessLong", 187, []OperandType{Addr32, Reg8, Reg8}, noMeaning(3), false)
	def("JLessN", 188, []OperandType{Addr8, Reg8, Reg8}, noMeaning(3), false)
	def("JLessNLong", 189, []OperandType{Addr32, Reg8, Reg8}, noMeaning(3), false)
	def("JNotLessN", 190, []OperandType{Addr8, Reg8, Reg8}, noMeaning(3), false)
	def("JNotLessNLong", 191, []OperandType{Addr32, Reg8, Reg8}, noMeaning(3), false)

	def("JLessEqual", 192, []OperandType{Addr8, Reg8, Reg8}, noMeaning(3), false)
	def("JLessEqualLong", 193, []OperandType{Addr32, Reg8, Reg8}, noMeaning(3), false)
	def("JNotLessEqual", 194, []OperandType{Addr8, Reg8, Reg8}, noMeaning(3), false)
	def("JNotLessEqualLong", 195, []OperandType{Addr32, Reg8, Reg8}, noMeaning(3), false)
	def("JLessEqualN", 196, []OperandType{Addr8, Reg8, Reg8}, noMeaning(3), false)
	def("JLessEqualNLong", 197, []OperandType{Addr32, Reg8, Reg8}, noMeaning(3), false)
	def("JNotLessEqualN", 198, []OperandType{Addr8, Reg8, Reg8}, noMeaning(3), false)
	def("JNotLessEqualNLong", 199, []OperandType{Addr32, Reg8, Reg8}, noMeaning(3), false)

	def("JGreater", 200, []OperandType{Addr8, Reg8, Reg8}, noMeaning(3), false)
	def("JGreaterLong", 201, []OperandType{Addr32, Reg8, Reg8}, noMeaning(3), false)
	def("JNotGreater", 202, []OperandType{Addr8, Reg8, Reg8}, noMeaning(3), false)
	def("JNotGreaterLong", 203, []OperandType{Addr32, Reg8, Reg8}, noMeaning(3), false)
	def("JGreaterEqual", 204, []OperandType{Addr8, Reg8, Reg8}, noMeaning(3), false)
	def("JGreaterEqualLong", 205, []OperandType{Addr32, Reg8, Reg8}, noMeaning(3), false)
	def("JNotGreaterEqual", 206, []OperandType{Addr8, Reg8, Reg8}, noMeaning(3), false)
	def("JNotGreaterEqualLong", 207, []OperandType{Addr32, Reg8, Reg8}, noMeaning(3), false)

	def("JEqual", 208, []OperandType{Addr8, Reg8, Reg8}, noMeaning(3), false)
	def("JEqualLong", 209, []OperandType{Addr32, Reg8, Reg8}, noMeaning(3), false)
	def("JNotEqual", 210, []OperandType{Addr8, Reg8, Reg8}, noMeaning(3), false)
	def("JNotEqualLong", 211, []OperandType{Addr32, Reg8, Reg8}, noMeaning(3), false)
	def("JStrictEqual", 212, []OperandType{Addr8, Reg8, Reg8}, noMeaning(3), false)
	def("JStrictEqualLong", 213, []OperandType{Addr32, Reg8, Reg8}, noMeaning(3), false)
	def("JStrictNotEqual", 214, []OperandType{Addr8, Reg8, Reg8}, noMeaning(3), false)
	def("JStrictNotEqualLong", 215, []OperandType{Addr32, Reg8, Reg8}, noMeaning(3), false)

	def("JmpBuiltinIs", 216, []OperandType{Addr8, UInt8, Reg8}, noMeaning(3), false)
	def("JmpBuiltinIsLong", 217, []OperandType{Addr32, UInt8, Reg8}, noMeaning(3), false)
	def("JmpBuiltinIsNot", 218, []OperandType{Addr8, UInt8, Reg8}, noMeaning(3), false)
	def("JmpBuiltinIsNotLong", 219, []OperandType{Addr32, UInt8, Reg8}, noMeaning(3), false)

	return t
}
