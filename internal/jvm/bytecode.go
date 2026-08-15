package jvm

import "fmt"

type Opcode byte

const (
	Nop             Opcode = 0x00
	AconstNull      Opcode = 0x01
	IconstM1        Opcode = 0x02
	Iconst0         Opcode = 0x03
	Iconst1         Opcode = 0x04
	Iconst2         Opcode = 0x05
	Iconst3         Opcode = 0x06
	Iconst4         Opcode = 0x07
	Iconst5         Opcode = 0x08
	Lconst0         Opcode = 0x09
	Lconst1         Opcode = 0x0a
	Fconst0         Opcode = 0x0b
	Fconst1         Opcode = 0x0c
	Fconst2         Opcode = 0x0d
	Dconst0         Opcode = 0x0e
	Dconst1         Opcode = 0x0f
	Bipush          Opcode = 0x10
	Sipush          Opcode = 0x11
	Ldc             Opcode = 0x12
	LdcW            Opcode = 0x13
	Ldc2W           Opcode = 0x14
	Iload           Opcode = 0x15
	Lload           Opcode = 0x16
	Fload           Opcode = 0x17
	Dload           Opcode = 0x18
	Aload           Opcode = 0x19
	Iload0          Opcode = 0x1a
	Iload1          Opcode = 0x1b
	Iload2          Opcode = 0x1c
	Iload3          Opcode = 0x1d
	Lload0          Opcode = 0x1e
	Lload1          Opcode = 0x1f
	Lload2          Opcode = 0x20
	Lload3          Opcode = 0x21
	Fload0          Opcode = 0x22
	Fload1          Opcode = 0x23
	Fload2          Opcode = 0x24
	Fload3          Opcode = 0x25
	Dload0          Opcode = 0x26
	Dload1          Opcode = 0x27
	Dload2          Opcode = 0x28
	Dload3          Opcode = 0x29
	Aload0          Opcode = 0x2a
	Aload1          Opcode = 0x2b
	Aload2          Opcode = 0x2c
	Aload3          Opcode = 0x2d
	Iaload          Opcode = 0x2e
	Laload          Opcode = 0x2f
	Faload          Opcode = 0x30
	Daload          Opcode = 0x31
	Aaload          Opcode = 0x32
	Baload          Opcode = 0x33
	Caload          Opcode = 0x34
	Saload          Opcode = 0x35
	Istore          Opcode = 0x36
	Lstore          Opcode = 0x37
	Fstore          Opcode = 0x38
	Dstore          Opcode = 0x39
	Astore          Opcode = 0x3a
	Istore0         Opcode = 0x3b
	Istore1         Opcode = 0x3c
	Istore2         Opcode = 0x3d
	Istore3         Opcode = 0x3e
	Lstore0         Opcode = 0x3f
	Lstore1         Opcode = 0x40
	Lstore2         Opcode = 0x41
	Lstore3         Opcode = 0x42
	Fstore0         Opcode = 0x43
	Fstore1         Opcode = 0x44
	Fstore2         Opcode = 0x45
	Fstore3         Opcode = 0x46
	Dstore0         Opcode = 0x47
	Dstore1         Opcode = 0x48
	Dstore2         Opcode = 0x49
	Dstore3         Opcode = 0x4a
	Astore0         Opcode = 0x4b
	Astore1         Opcode = 0x4c
	Astore2         Opcode = 0x4d
	Astore3         Opcode = 0x4e
	Iastore         Opcode = 0x4f
	Lastore         Opcode = 0x50
	Fastore         Opcode = 0x51
	Dastore         Opcode = 0x52
	Aastore         Opcode = 0x53
	Bastore         Opcode = 0x54
	Castore         Opcode = 0x55
	Sastore         Opcode = 0x56
	Pop             Opcode = 0x57
	Pop2            Opcode = 0x58
	Dup             Opcode = 0x59
	DupX1           Opcode = 0x5a
	DupX2           Opcode = 0x5b
	Dup2            Opcode = 0x5c
	Dup2X1          Opcode = 0x5d
	Dup2X2          Opcode = 0x5e
	Swap            Opcode = 0x5f
	Iadd            Opcode = 0x60
	Ladd            Opcode = 0x61
	Fadd            Opcode = 0x62
	Dadd            Opcode = 0x63
	Isub            Opcode = 0x64
	Lsub            Opcode = 0x65
	Fsub            Opcode = 0x66
	Dsub            Opcode = 0x67
	Imul            Opcode = 0x68
	Lmul            Opcode = 0x69
	Fmul            Opcode = 0x6a
	Dmul            Opcode = 0x6b
	Idiv            Opcode = 0x6c
	Ldiv            Opcode = 0x6d
	Fdiv            Opcode = 0x6e
	Ddiv            Opcode = 0x6f
	Irem            Opcode = 0x70
	Lrem            Opcode = 0x71
	Frem            Opcode = 0x72
	Drem            Opcode = 0x73
	Ineg            Opcode = 0x74
	Lneg            Opcode = 0x75
	Fneg            Opcode = 0x76
	Dneg            Opcode = 0x77
	Ishl            Opcode = 0x78
	Lshl            Opcode = 0x79
	Ishr            Opcode = 0x7a
	Lshr            Opcode = 0x7b
	Iushr           Opcode = 0x7c
	Lushr           Opcode = 0x7d
	Iand            Opcode = 0x7e
	Land            Opcode = 0x7f
	Ior             Opcode = 0x80
	Lor             Opcode = 0x81
	Ixor            Opcode = 0x82
	Lxor            Opcode = 0x83
	Iinc            Opcode = 0x84
	I2l             Opcode = 0x85
	I2f             Opcode = 0x86
	I2d             Opcode = 0x87
	L2i             Opcode = 0x88
	L2f             Opcode = 0x89
	L2d             Opcode = 0x8a
	F2i             Opcode = 0x8b
	F2l             Opcode = 0x8c
	F2d             Opcode = 0x8d
	D2i             Opcode = 0x8e
	D2l             Opcode = 0x8f
	D2f             Opcode = 0x90
	I2b             Opcode = 0x91
	I2c             Opcode = 0x92
	I2s             Opcode = 0x93
	Lcmp            Opcode = 0x94
	Fcmpl           Opcode = 0x95
	Fcmpg           Opcode = 0x96
	Dcmpl           Opcode = 0x97
	Dcmpg           Opcode = 0x98
	Ifeq            Opcode = 0x99
	Ifne            Opcode = 0x9a
	Iflt            Opcode = 0x9b
	Ifge            Opcode = 0x9c
	Ifgt            Opcode = 0x9d
	Ifle            Opcode = 0x9e
	IfIcmpeq        Opcode = 0x9f
	IfIcmpne        Opcode = 0xa0
	IfIcmplt        Opcode = 0xa1
	IfIcmpge        Opcode = 0xa2
	IfIcmpgt        Opcode = 0xa3
	IfIcmple        Opcode = 0xa4
	IfAcmpeq        Opcode = 0xa5
	IfAcmpne        Opcode = 0xa6
	Goto            Opcode = 0xa7
	Jsr             Opcode = 0xa8
	Ret             Opcode = 0xa9
	Tableswitch     Opcode = 0xaa
	Lookupswitch    Opcode = 0xab
	Ireturn         Opcode = 0xac
	Lreturn         Opcode = 0xad
	Freturn         Opcode = 0xae
	Dreturn         Opcode = 0xaf
	Areturn         Opcode = 0xb0
	Return          Opcode = 0xb1
	Getstatic       Opcode = 0xb2
	Putstatic       Opcode = 0xb3
	Getfield        Opcode = 0xb4
	Putfield        Opcode = 0xb5
	Invokevirtual   Opcode = 0xb6
	Invokespecial   Opcode = 0xb7
	Invokestatic    Opcode = 0xb8
	Invokeinterface Opcode = 0xb9
	Invokedynamic   Opcode = 0xba
	New             Opcode = 0xbb
	Newarray        Opcode = 0xbc
	Anewarray       Opcode = 0xbd
	Arraylength     Opcode = 0xbe
	Athrow          Opcode = 0xbf
	Checkcast       Opcode = 0xc0
	Instanceof      Opcode = 0xc1
	Monitorenter    Opcode = 0xc2
	Monitorexit     Opcode = 0xc3
	Wide            Opcode = 0xc4
	Multianewarray  Opcode = 0xc5
	Ifnull          Opcode = 0xc6
	Ifnonnull       Opcode = 0xc7
	GotoW           Opcode = 0xc8
	JsrW            Opcode = 0xc9
	Breakpoint      Opcode = 0xca
)

type Instruction struct {
	Offset   int
	Opcode   Opcode
	Operands []byte
	Raw      byte
}

func (i Instruction) Size() int {
	return 1 + len(i.Operands)
}

var opcodeNames = map[Opcode]string{
	Nop: "nop", AconstNull: "aconst_null",
	IconstM1: "iconst_m1", Iconst0: "iconst_0", Iconst1: "iconst_1",
	Iconst2: "iconst_2", Iconst3: "iconst_3", Iconst4: "iconst_4", Iconst5: "iconst_5",
	Lconst0: "lconst_0", Lconst1: "lconst_1",
	Fconst0: "fconst_0", Fconst1: "fconst_1", Fconst2: "fconst_2",
	Dconst0: "dconst_0", Dconst1: "dconst_1",
	Bipush: "bipush", Sipush: "sipush",
	Ldc: "ldc", LdcW: "ldc_w", Ldc2W: "ldc2_w",
	Iload: "iload", Lload: "lload", Fload: "fload", Dload: "dload", Aload: "aload",
	Iload0: "iload_0", Iload1: "iload_1", Iload2: "iload_2", Iload3: "iload_3",
	Lload0: "lload_0", Lload1: "lload_1", Lload2: "lload_2", Lload3: "lload_3",
	Fload0: "fload_0", Fload1: "fload_1", Fload2: "fload_2", Fload3: "fload_3",
	Dload0: "dload_0", Dload1: "dload_1", Dload2: "dload_2", Dload3: "dload_3",
	Aload0: "aload_0", Aload1: "aload_1", Aload2: "aload_2", Aload3: "aload_3",
	Iaload: "iaload", Laload: "laload", Faload: "faload", Daload: "daload", Aaload: "aaload",
	Baload: "baload", Caload: "caload", Saload: "saload",
	Istore: "istore", Lstore: "lstore", Fstore: "fstore", Dstore: "dstore", Astore: "astore",
	Istore0: "istore_0", Istore1: "istore_1", Istore2: "istore_2", Istore3: "istore_3",
	Lstore0: "lstore_0", Lstore1: "lstore_1", Lstore2: "lstore_2", Lstore3: "lstore_3",
	Fstore0: "fstore_0", Fstore1: "fstore_1", Fstore2: "fstore_2", Fstore3: "fstore_3",
	Dstore0: "dstore_0", Dstore1: "dstore_1", Dstore2: "dstore_2", Dstore3: "dstore_3",
	Astore0: "astore_0", Astore1: "astore_1", Astore2: "astore_2", Astore3: "astore_3",
	Iastore: "iastore", Lastore: "lastore", Fastore: "fastore", Dastore: "dastore",
	Aastore: "aastore", Bastore: "bastore", Castore: "castore", Sastore: "sastore",
	Pop: "pop", Pop2: "pop2",
	Dup: "dup", DupX1: "dup_x1", DupX2: "dup_x2",
	Dup2: "dup2", Dup2X1: "dup2_x1", Dup2X2: "dup2_x2", Swap: "swap",
	Iadd: "iadd", Ladd: "ladd", Fadd: "fadd", Dadd: "dadd",
	Isub: "isub", Lsub: "lsub", Fsub: "fsub", Dsub: "dsub",
	Imul: "imul", Lmul: "lmul", Fmul: "fmul", Dmul: "dmul",
	Idiv: "idiv", Ldiv: "ldiv", Fdiv: "fdiv", Ddiv: "ddiv",
	Irem: "irem", Lrem: "lrem", Frem: "frem", Drem: "drem",
	Ineg: "ineg", Lneg: "lneg", Fneg: "fneg", Dneg: "dneg",
	Ishl: "ishl", Lshl: "lshl", Ishr: "ishr", Lshr: "lshr",
	Iushr: "iushr", Lushr: "lushr",
	Iand: "iand", Land: "land", Ior: "ior", Lor: "lor", Ixor: "ixor", Lxor: "lxor",
	Iinc: "iinc",
	I2l: "i2l", I2f: "i2f", I2d: "i2d",
	L2i: "l2i", L2f: "l2f", L2d: "l2d",
	F2i: "f2i", F2l: "f2l", F2d: "f2d",
	D2i: "d2i", D2l: "d2l", D2f: "d2f",
	I2b: "i2b", I2c: "i2c", I2s: "i2s",
	Lcmp: "lcmp", Fcmpl: "fcmpl", Fcmpg: "fcmpg", Dcmpl: "dcmpl", Dcmpg: "dcmpg",
	Ifeq: "ifeq", Ifne: "ifne", Iflt: "iflt", Ifge: "ifge", Ifgt: "ifgt", Ifle: "ifle",
	IfIcmpeq: "if_icmpeq", IfIcmpne: "if_icmpne", IfIcmplt: "if_icmplt",
	IfIcmpge: "if_icmpge", IfIcmpgt: "if_icmpgt", IfIcmple: "if_icmple",
	IfAcmpeq: "if_acmpeq", IfAcmpne: "if_acmpne",
	Goto: "goto", Jsr: "jsr", Ret: "ret",
	Tableswitch: "tableswitch", Lookupswitch: "lookupswitch",
	Ireturn: "ireturn", Lreturn: "lreturn", Freturn: "freturn",
	Dreturn: "dreturn", Areturn: "areturn", Return: "return",
	Getstatic: "getstatic", Putstatic: "putstatic", Getfield: "getfield", Putfield: "putfield",
	Invokevirtual: "invokevirtual", Invokespecial: "invokespecial",
	Invokestatic: "invokestatic", Invokeinterface: "invokeinterface", Invokedynamic: "invokedynamic",
	New: "new", Newarray: "newarray", Anewarray: "anewarray",
	Arraylength: "arraylength", Athrow: "athrow",
	Checkcast: "checkcast", Instanceof: "instanceof",
	Monitorenter: "monitorenter", Monitorexit: "monitorexit",
	Wide: "wide", Multianewarray: "multianewarray",
	Ifnull: "ifnull", Ifnonnull: "ifnonnull", GotoW: "goto_w",
}

func OpcodeName(op Opcode) string {
	if name, ok := opcodeNames[op]; ok {
		return name
	}
	return fmt.Sprintf("opcode_0x%02x", byte(op))
}

func DecodeInstructions(code []byte) []Instruction {
	var instructions []Instruction
	i := 0
	for i < len(code) {
		op := Opcode(code[i])
		inst := Instruction{Offset: i, Opcode: op, Raw: code[i]}
		i++

		switch op {
		case Bipush, Ldc, Iload, Lload, Fload, Dload, Aload,
			Istore, Lstore, Fstore, Dstore, Astore, Ret:
			if i < len(code) {
				inst.Operands = code[i : i+1]
				i++
			}
		case Sipush, LdcW, Ifeq, Ifne, Iflt, Ifge, Ifgt, Ifle,
			IfIcmpeq, IfIcmpne, IfIcmplt, IfIcmpge, IfIcmpgt, IfIcmple,
			IfAcmpeq, IfAcmpne, Goto, Jsr, Ifnull, Ifnonnull:
			if i+1 < len(code) {
				inst.Operands = code[i : i+2]
				i += 2
			}
		case Ldc2W, Getstatic, Putstatic, Getfield, Putfield,
			Invokevirtual, Invokespecial, Invokestatic, New, Anewarray,
			Checkcast, Instanceof:
			if i+1 < len(code) {
				inst.Operands = code[i : i+2]
				i += 2
			}
		case Invokeinterface:
			if i+3 < len(code) {
				inst.Operands = code[i : i+4]
				i += 4
			}
		case Invokedynamic:
			if i+3 < len(code) {
				inst.Operands = code[i : i+4]
				i += 4
			}
		case Multianewarray:
			if i+2 < len(code) {
				inst.Operands = code[i : i+3]
				i += 3
			}
		case Iinc:
			if i+1 < len(code) {
				inst.Operands = code[i : i+2]
				i += 2
			}
		case GotoW, JsrW:
			if i+3 < len(code) {
				inst.Operands = code[i : i+4]
				i += 4
			}
		case Newarray:
			if i < len(code) {
				inst.Operands = code[i : i+1]
				i++
			}
		case Tableswitch:
			pad := (4 - (i % 4)) % 4
			i += pad
			base := i
			if base+12 < len(code) {
				_ = int32(code[base])<<24 | int32(code[base+1])<<16 | int32(code[base+2])<<8 | int32(code[base+3])
				low := int32(code[base+4])<<24 | int32(code[base+5])<<16 | int32(code[base+6])<<8 | int32(code[base+7])
				high := int32(code[base+8])<<24 | int32(code[base+9])<<16 | int32(code[base+10])<<8 | int32(code[base+11])
				tableLen := int(high-low+1)*4 + 12
				if base+tableLen <= len(code) {
					inst.Operands = code[base : base+tableLen]
					i = base + tableLen
				}
			}
		case Lookupswitch:
			pad := (4 - (i % 4)) % 4
			i += pad
			base := i
			if base+8 < len(code) {
				_ = int32(code[base])<<24 | int32(code[base+1])<<16 | int32(code[base+2])<<8 | int32(code[base+3])
				npairs := int32(code[base+4])<<24 | int32(code[base+5])<<16 | int32(code[base+6])<<8 | int32(code[base+7])
				tableLen := int(npairs)*8 + 8
				if base+tableLen <= len(code) {
					inst.Operands = code[base : base+tableLen]
					i = base + tableLen
				}
			}
		case Wide:
			if i < len(code) {
				wideOp := code[i]
				inst.Operands = []byte{code[i]}
				i++
				if wideOp == 0x84 {
					if i+1 < len(code) {
						inst.Operands = append(inst.Operands, code[i], code[i+1])
						i += 2
					}
				} else {
					if i+1 < len(code) {
						inst.Operands = append(inst.Operands, code[i], code[i+1])
						i += 2
					}
				}
			}
		}

		instructions = append(instructions, inst)
	}

	return instructions
}

func (i Instruction) String() string {
	name := OpcodeName(i.Opcode)
	return fmt.Sprintf("%s %x", name, i.Operands)
}
